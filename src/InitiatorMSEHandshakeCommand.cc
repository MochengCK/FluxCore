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
#include "InitiatorMSEHandshakeCommand.h"
#include "SocketLike.h"
#include "UtpSocketLike.h"
#include "UtpConnection.h"
#include "PeerInitiateConnectionCommand.h"
#include "PeerInteractionCommand.h"
#include "DownloadEngine.h"
#include "DlAbortEx.h"
#include "message.h"
#include "prefs.h"
#include "SocketCore.h"
#include "Logger.h"
#include "LogFactory.h"
#include "Peer.h"
#include "PeerConnection.h"
#include "BtRuntime.h"
#include "PeerStorage.h"
#include "DefaultPeerStorage.h"
#include "PieceStorage.h"
#include "Option.h"
#include "MSEHandshake.h"
#include "ARC4Encryptor.h"
#include "RequestGroup.h"
#include "DownloadContext.h"
#include "bittorrent_helper.h"
#include "util.h"
#include "fmt.h"
#include "array_fun.h"

namespace aria2 {

InitiatorMSEHandshakeCommand::InitiatorMSEHandshakeCommand(
    cuid_t cuid, RequestGroup* requestGroup, const std::shared_ptr<Peer>& p,
    DownloadEngine* e, const std::shared_ptr<BtRuntime>& btRuntime,
    const std::shared_ptr<SocketCore>& s,
    const std::shared_ptr<utp::UtpConnection>& utpConn)
    : PeerAbstractCommand(cuid, p, e, s),
      requestGroup_(requestGroup),
      btRuntime_(btRuntime),
      sequence_(INITIATOR_SEND_KEY),
      isUtp_(utpConn != nullptr),
      utpConn_(utpConn),
      transport_(isUtp_
                     ? std::static_pointer_cast<SocketLike>(
                           std::make_shared<UtpSocketLike>(utpConn))
                     : std::make_shared<TcpSocketLike>(s)),
      mseHandshake_(
          make_unique<MSEHandshake>(cuid, transport_, getOption().get()))
{
  // uTP 无 fd 事件可注册：由引擎每轮调度轮询本命令（与
  // PeerInteractionCommand 的 uTP 路径一致）；TCP 维持原事件驱动。
  if (!isUtp_) {
    disableReadCheckSocket();
    setWriteCheckSocket(getSocket());
  }
  setTimeout(std::chrono::seconds(
      getOption()->getAsInt(PREF_PEER_CONNECTION_TIMEOUT)));

  btRuntime_->increaseConnections();
  requestGroup_->increaseNumCommand();
}

InitiatorMSEHandshakeCommand::~InitiatorMSEHandshakeCommand()
{
  requestGroup_->decreaseNumCommand();
  btRuntime_->decreaseConnections();
}

bool InitiatorMSEHandshakeCommand::executeInternal()
{
  // uTP：连接失败/超时/被 RST 时 transport 不可用，快速失败走回退
  // （prepareForNextPeer 重建 PeerInitiateConnectionCommand 回 TCP）。
  if (isUtp_ && !transport_->isOpen()) {
    throw DL_ABORT_EX("uTP connection closed during MSE handshake");
  }
  if (mseHandshake_->getWantRead()) {
    mseHandshake_->read();
  }
  bool done = false;
  while (!done) {
    switch (sequence_) {
    case INITIATOR_SEND_KEY: {
      // 连接建立阶段（TCP SYN 未完成）用短超时：死链 30s 内快速失败
      // 并释放连接额度；连接建立、握手真正开始后（下方 writable 分支）
      // 恢复完整 bt-timeout。
      {
        auto btTimeout = getOption()->getAsInt(PREF_BT_TIMEOUT);
        setTimeout(std::chrono::seconds(btTimeout < 30 ? btTimeout : 30));
      }
      // uTP 没有可写性事件：写入先缓存进 UtpConnection::pendingSend_，
      // 连接建立后由 processTick 冲刷，无需等待。
      if (!isUtp_ && !getSocket()->isWritable(0)) {
        addCommandSelf();
        return false;
      }
      setTimeout(std::chrono::seconds(getOption()->getAsInt(PREF_BT_TIMEOUT)));
      mseHandshake_->initEncryptionFacility(true);
      mseHandshake_->sendPublicKey();
      sequence_ = INITIATOR_SEND_KEY_PENDING;
      break;
    }
    case INITIATOR_SEND_KEY_PENDING:
      if (mseHandshake_->send()) {
        sequence_ = INITIATOR_WAIT_KEY;
      }
      else {
        done = true;
      }
      break;
    case INITIATOR_WAIT_KEY: {
      if (mseHandshake_->receivePublicKey()) {
        mseHandshake_->initCipher(
            bittorrent::getInfoHash(requestGroup_->getDownloadContext()));
        ;
        mseHandshake_->sendInitiatorStep2();
        sequence_ = INITIATOR_SEND_STEP2_PENDING;
      }
      else {
        done = true;
      }
      break;
    }
    case INITIATOR_SEND_STEP2_PENDING:
      if (mseHandshake_->send()) {
        sequence_ = INITIATOR_FIND_VC_MARKER;
      }
      else {
        done = true;
      }
      break;
    case INITIATOR_FIND_VC_MARKER: {
      if (mseHandshake_->findInitiatorVCMarker()) {
        sequence_ = INITIATOR_RECEIVE_PAD_D_LENGTH;
      }
      else {
        done = true;
      }
      break;
    }
    case INITIATOR_RECEIVE_PAD_D_LENGTH: {
      if (mseHandshake_->receiveInitiatorCryptoSelectAndPadDLength()) {
        sequence_ = INITIATOR_RECEIVE_PAD_D;
      }
      else {
        done = true;
      }
      break;
    }
    case INITIATOR_RECEIVE_PAD_D: {
      if (mseHandshake_->receivePad()) {
        std::unique_ptr<SocketLike> peerTransport =
            isUtp_
                ? std::unique_ptr<SocketLike>(
                      make_unique<UtpSocketLike>(utpConn_))
                : make_unique<TcpSocketLike>(getSocket());
        auto peerConnection = make_unique<PeerConnection>(
            getCuid(), getPeer(), std::move(peerTransport));
        if (mseHandshake_->getNegotiatedCryptoType() ==
            MSEHandshake::CRYPTO_ARC4) {
          size_t buflen = mseHandshake_->getBufferLength();
          mseHandshake_->getDecryptor()->encrypt(
              buflen, mseHandshake_->getBuffer(), mseHandshake_->getBuffer());
          peerConnection->presetBuffer(mseHandshake_->getBuffer(), buflen);
          peerConnection->enableEncryption(mseHandshake_->popEncryptor(),
                                           mseHandshake_->popDecryptor());
        }
        else {
          peerConnection->presetBuffer(mseHandshake_->getBuffer(),
                                       mseHandshake_->getBufferLength());
        }
        getDownloadEngine()->addCommand(make_unique<PeerInteractionCommand>(
            getCuid(), requestGroup_, getPeer(), getDownloadEngine(),
            btRuntime_, pieceStorage_, peerStorage_,
            isUtp_ ? std::shared_ptr<SocketCore>() : getSocket(),
            PeerInteractionCommand::INITIATOR_SEND_HANDSHAKE,
            std::move(peerConnection)));
        return true;
      }
      else {
        done = true;
      }
      break;
    }
    }
  }
  // uTP：不注册 fd 事件，靠每轮调度轮询推进（数据由 UtpCommand 泵送）。
  if (!isUtp_) {
    if (mseHandshake_->getWantRead()) {
      setReadCheckSocket(getSocket());
    }
    else {
      disableReadCheckSocket();
    }
    if (mseHandshake_->getWantWrite()) {
      setWriteCheckSocket(getSocket());
    }
    else {
      disableWriteCheckSocket();
    }
  }
  addCommandSelf();
  return false;
}

void InitiatorMSEHandshakeCommand::tryNewPeer()
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
}

bool InitiatorMSEHandshakeCommand::prepareForNextPeer(time_t wait)
{
  if (sequence_ == INITIATOR_SEND_KEY) {
    // We don't try legacy handshake when connection did not
    // established.
    tryNewPeer();
    return true;
  }
  else if (getOption()->getAsBool(PREF_BT_FORCE_ENCRYPTION) ||
           getOption()->getAsBool(PREF_BT_REQUIRE_CRYPTO)) {
    A2_LOG_INFO(fmt("CUID#%" PRId64 " - Establishing connection using legacy"
                    " BitTorrent handshake is disabled by preference.",
                    getCuid()));
    tryNewPeer();
    return true;
  }
  else {
    // try legacy BitTorrent handshake
    A2_LOG_INFO(fmt("CUID#%" PRId64
                    " - Retry using legacy BitTorrent handshake.",
                    getCuid()));
    auto command = make_unique<PeerInitiateConnectionCommand>(
        getCuid(), requestGroup_, getPeer(), getDownloadEngine(), btRuntime_,
        false);
    command->setPeerStorage(peerStorage_);
    command->setPieceStorage(pieceStorage_);
    getDownloadEngine()->addCommand(std::move(command));
    return true;
  }
}

void InitiatorMSEHandshakeCommand::onAbort()
{
  if (sequence_ == INITIATOR_SEND_KEY ||
      getOption()->getAsBool(PREF_BT_FORCE_ENCRYPTION) ||
      getOption()->getAsBool(PREF_BT_REQUIRE_CRYPTO)) {
    peerStorage_->returnPeer(getPeer());
  }
}

void InitiatorMSEHandshakeCommand::onConnectionFailed()
{
  // uTP 传输级失败（SYN/MSE 握手未完成）：记入 peer 的 uTP 失败计数，
  // 达上限后不再探测、冷却期内跳过（见 Peer::utpProbeAllowed）。
  if (isUtp_) {
    getPeer()->recordUtpFailure();
  }
  // MSE 握手失败（对端不回应/协议不兼容/超时）：计入 PeerStorage 失败
  // 统计，RPC getPeers 暴露给前端。
  if (auto defaultPeerStorage =
          std::dynamic_pointer_cast<DefaultPeerStorage>(peerStorage_)) {
    defaultPeerStorage->recordPeerFailure(getPeer());
  }
}

bool InitiatorMSEHandshakeCommand::exitBeforeExecute()
{
  return btRuntime_->isHalt();
}

void InitiatorMSEHandshakeCommand::setPeerStorage(
    const std::shared_ptr<PeerStorage>& peerStorage)
{
  peerStorage_ = peerStorage;
}

void InitiatorMSEHandshakeCommand::setPieceStorage(
    const std::shared_ptr<PieceStorage>& pieceStorage)
{
  pieceStorage_ = pieceStorage;
}

const std::shared_ptr<Option>& InitiatorMSEHandshakeCommand::getOption() const
{
  return requestGroup_->getOption();
}

} // namespace aria2
