/* <!-- copyright */
/*
 * aria2 - The high speed download utility
 *
 * Copyright (C) 2006 Tatsuhiro Tsujikawa
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 *
 * In addition, as a special exception, the copyright holders give
 * permission to link the code of portions of this program with the
 * OpenSSL library under certain conditions as described in each
 * individual source file, and distribute linked combinations
 * including the two.
 * You must obey the GNU General Public License in all respects
 * for all of the code used other than OpenSSL.  If you modify
 * file(s) with this exception, you may extend this exception to your
 * version of the file(s), but you are not obligated to do so.  If you
 * do not wish to do so, delete this exception statement from your
 * version.  If you delete this exception statement from all source
 * files in the program, then also delete it here.
 */
/* copyright --> */
#include "PeerInitiateConnectionCommand.h"
#include "UtpContext.h"
#include "InitiatorMSEHandshakeCommand.h"
#include "PeerInteractionCommand.h"
#include "DownloadEngine.h"
#include "DlAbortEx.h"
#include "message.h"
#include "prefs.h"
#include "Option.h"
#include "SocketCore.h"
#include "Logger.h"
#include "LogFactory.h"
#include "Peer.h"
#include "BtRuntime.h"
#include "PeerStorage.h"
#include "DefaultPeerStorage.h"
#include "PieceStorage.h"
#include "PeerConnection.h"
#include "UtpSocketLike.h"
#include "RequestGroup.h"
#include "util.h"
#include "fmt.h"

namespace aria2 {

PeerInitiateConnectionCommand::PeerInitiateConnectionCommand(
    cuid_t cuid, RequestGroup* requestGroup, const std::shared_ptr<Peer>& peer,
    DownloadEngine* e, const std::shared_ptr<BtRuntime>& btRuntime,
    bool mseHandshakeEnabled)
    : PeerAbstractCommand(cuid, peer, e),
      requestGroup_(requestGroup),
      btRuntime_(btRuntime),
      mseHandshakeEnabled_(mseHandshakeEnabled)
{
  btRuntime_->increaseConnections();
  requestGroup_->increaseNumCommand();
}

PeerInitiateConnectionCommand::~PeerInitiateConnectionCommand()
{
  requestGroup_->decreaseNumCommand();
  btRuntime_->decreaseConnections();
}

bool PeerInitiateConnectionCommand::executeInternal()
{
  A2_LOG_INFO(fmt(MSG_CONNECTING_TO_SERVER, getCuid(),
                  getPeer()->getIPAddress().c_str(), getPeer()->getPort()));

  // uTP (BEP 29) first: when enabled and the transport is hosted, try
  // the peer over UDP with delay-based congestion control. The BT
  // handshake runs over the uTP stream (plain, no MSE). If the uTP
  // connection dies, the peer returns to storage and a later checkout
  // retries it (TCP path included).
  auto utpCtx = getDownloadEngine()->getUtpContext();
  const auto* opt = getDownloadEngine()->getOption();
  // uTP (BEP 29) 本身是明文传输，不参与 TCP 侧的 MSE 加密协商。
  // 因此只要不"强制加密"（bt-require-crypto / bt-force-encryption），
  // 就允许 uTP 明文连接——即使"自适应加密"（bt-min-crypto-level=arc4）
  // 模式下 TCP 拒绝明文，uTP 仍可明文建立，与 qBittorrent/uTorrent 的
  // 行为一致。此前额外要求 min-crypto-level == plain，导致默认的
  // "自适应加密"配置下 uTP 被完全禁用、所有 peer 回退 TCP，节点表格
  // 永远只能显示 TCP/tcp-ext。
  bool plainAllowed = !opt->getAsBool(PREF_BT_REQUIRE_CRYPTO) &&
                      !opt->getAsBool(PREF_BT_FORCE_ENCRYPTION);
  // 出站 uTP 策略（qBittorrent 对齐：出站优先 uTP）：
  //  - PEX 广播了 uTP 能力（added.f 0x04）的 peer：完整 SYN 重试预算；
  //  - 能力未知的 peer（tracker/DHT 来源）：3s 快速探测预算，超时立即
  //    失败，peer 回到候选池后由下一轮连接周期（~1s）走 TCP——把
  //    "对端不支持 uTP"的代价从 ~7.5s 死链降到 ~4s 总延迟。
  //  此前仅对 PEX 标记的 peer 发起 uTP，tracker/DHT 来源的 peer 永远
  //  走 TCP，uTP 连接数远少于 qB。uTP 无连接语义下 connect() 总能
  //  "成功"返回，故快速失败预算必须由 UtpConnection 的 SYN deadline
  //  实施（hasUtpTried 防止重复探测）。入站 uTP 不受影响。
  // IPv6 peer 不探测：共享 UDP socket 绑定的是 AF_INET。
  const bool peerIsV6 =
      getPeer()->getIPAddress().find(':') != std::string::npos;
  if (utpCtx && opt->getAsBool(PREF_ENABLE_UTP) && plainAllowed && !peerIsV6 &&
      !getPeer()->hasUtpTried()) {
    const uint32_t synBudgetUs =
        getPeer()->isUtpCapable() ? 0 /* 默认完整预算 */ : 3000000;
    auto conn = utpCtx->connect(getPeer()->getIPAddress(),
                                getPeer()->getPort(), synBudgetUs);
    if (conn) {
      getPeer()->setUtpTried(true);
      // 传输已确定走 uTP：标记到 Peer，供 RPC getPeers 的协议标签
      // （utp/utp-ext）与失败统计分流（utpFails）使用。此前漏标导致
      // 出站 uTP 连接在 UI 永远显示为 tcp，"零 uTP 连接"的表象由此
      // 而来（入站 uTP 在 PeerReceiveHandshakeCommand 有正确标记）。
      getPeer()->setUtp(true);
      A2_LOG_INFO(fmt("CUID#%" PRId64 " - Trying uTP connection to %s:%u",
                      getCuid(), getPeer()->getIPAddress().c_str(),
                      getPeer()->getPort()));
      auto peerConnection = make_unique<PeerConnection>(
          getCuid(), getPeer(), make_unique<UtpSocketLike>(conn));
      getDownloadEngine()->addCommand(make_unique<PeerInteractionCommand>(
          getCuid(), requestGroup_, getPeer(), getDownloadEngine(), btRuntime_,
          pieceStorage_, peerStorage_, nullptr /* no TCP socket */,
          PeerInteractionCommand::INITIATOR_SEND_HANDSHAKE,
          std::move(peerConnection)));
      return true;
    }
  }

  createSocket();
  getSocket()->establishConnection(getPeer()->getIPAddress(),
                                   getPeer()->getPort(), false);
  getSocket()->applyIpDscp();
  // 不加密模式（REQUIRE=F && MIN_LEVEL=plain）：直接发 Legacy BT 握手，
  // 跳过 MSE DH 协商。自适应/强制加密模式仍走 MSE。
  // 仅当 mseHandshakeEnabled_ 为 true（默认值）时按配置调整；若调用方
  // 显式传 false（MSE 失败回退 Legacy），保持 false 不变。
  if (mseHandshakeEnabled_ && !opt->getAsBool(PREF_BT_REQUIRE_CRYPTO) &&
      !opt->getAsBool(PREF_BT_FORCE_ENCRYPTION) &&
      opt->get(PREF_BT_MIN_CRYPTO_LEVEL) == V_PLAIN) {
    mseHandshakeEnabled_ = false;
  }
  if (mseHandshakeEnabled_) {
    auto c = make_unique<InitiatorMSEHandshakeCommand>(
        getCuid(), requestGroup_, getPeer(), getDownloadEngine(), btRuntime_,
        getSocket());
    c->setPeerStorage(peerStorage_);
    c->setPieceStorage(pieceStorage_);
    getDownloadEngine()->addCommand(std::move(c));
  }
  else {
    getDownloadEngine()->addCommand(make_unique<PeerInteractionCommand>(
        getCuid(), requestGroup_, getPeer(), getDownloadEngine(), btRuntime_,
        pieceStorage_, peerStorage_, getSocket(),
        PeerInteractionCommand::INITIATOR_SEND_HANDSHAKE));
  }
  return true;
}

// TODO this method removed when PeerBalancerCommand is implemented
bool PeerInitiateConnectionCommand::prepareForNextPeer(time_t wait)
{
  if (peerStorage_->isPeerAvailable() && btRuntime_->lessThanEqMinPeers()) {
    cuid_t ncuid = getDownloadEngine()->newCUID();
    std::shared_ptr<Peer> peer = peerStorage_->checkoutPeer(ncuid);
    // sanity check
    if (peer) {
      auto command = make_unique<PeerInitiateConnectionCommand>(
          ncuid, requestGroup_, peer, getDownloadEngine(), btRuntime_);
      command->setPeerStorage(peerStorage_);
      command->setPieceStorage(pieceStorage_);
      getDownloadEngine()->addCommand(std::move(command));
    }
  }
  return true;
}

void PeerInitiateConnectionCommand::onAbort()
{
  peerStorage_->returnPeer(getPeer());
}

void PeerInitiateConnectionCommand::onConnectionFailed()
{
  // 连接建立阶段失败（TCP/uTP 连不通、握手超时等）：计入 PeerStorage
  // 失败统计，RPC getPeers 暴露给前端。
  if (auto defaultPeerStorage =
          std::dynamic_pointer_cast<DefaultPeerStorage>(peerStorage_)) {
    defaultPeerStorage->recordPeerFailure(getPeer());
  }
}

bool PeerInitiateConnectionCommand::exitBeforeExecute()
{
  return btRuntime_->isHalt();
}

void PeerInitiateConnectionCommand::setPeerStorage(
    const std::shared_ptr<PeerStorage>& peerStorage)
{
  peerStorage_ = peerStorage;
}

void PeerInitiateConnectionCommand::setPieceStorage(
    const std::shared_ptr<PieceStorage>& pieceStorage)
{
  pieceStorage_ = pieceStorage;
}

} // namespace aria2
