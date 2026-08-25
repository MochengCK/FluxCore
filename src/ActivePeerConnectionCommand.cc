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
#include "ActivePeerConnectionCommand.h"
#include "DefaultPeerStorage.h"
#include "PeerInitiateConnectionCommand.h"
#include "message.h"
#include "DownloadEngine.h"
#include "PeerStorage.h"
#include "PieceStorage.h"
#include "BtRuntime.h"
#include "Peer.h"
#include "Logger.h"
#include "LogFactory.h"
#include "prefs.h"
#include "Option.h"
#include "BtConstants.h"
#include "SocketCore.h"
#include "BtAnnounce.h"
#include "RequestGroup.h"
#include "DownloadContext.h"
#include "bittorrent_helper.h"
#include "wallclock.h"
#include "util.h"
#include "fmt.h"
#include "DownloadEngine.h"

namespace aria2 {

ActivePeerConnectionCommand::ActivePeerConnectionCommand(
    cuid_t cuid, RequestGroup* requestGroup, DownloadEngine* e,
    std::chrono::seconds interval)
    : Command(cuid),
      requestGroup_(requestGroup),
      interval_(std::move(interval)),
      e_(e),
      numNewConnection_(10)
{
  requestGroup_->increaseNumCommand();
}

ActivePeerConnectionCommand::~ActivePeerConnectionCommand()
{
  requestGroup_->decreaseNumCommand();
}

bool ActivePeerConnectionCommand::execute()
{
  if (btRuntime_->isHalt()) {
    return true;
  }
  if (checkPoint_.difference(global::wallclock()) >= interval_) {
    checkPoint_ = global::wallclock();
    NetStat& stat = requestGroup_->getDownloadContext()->getNetStat();
    const int maxDownloadLimit = requestGroup_->getMaxDownloadSpeedLimit();
    const int maxUploadLimit = requestGroup_->getMaxUploadSpeedLimit();
    int thresholdSpeed;
    if (!bittorrent::getTorrentAttrs(requestGroup_->getDownloadContext())
             ->metadata.empty()) {
      thresholdSpeed = requestGroup_->getOption()->getAsInt(
          PREF_BT_REQUEST_PEER_SPEED_LIMIT);
    }
    else {
      thresholdSpeed = 0;
    }
    if (maxDownloadLimit > 0) {
      thresholdSpeed = std::min(maxDownloadLimit, thresholdSpeed);
    }
    // 冷启动突发：首个 tick 一次性发起 3 倍连接（10 → 30），让
    // 下载快速起速；后续回到常规速率。
    int connBurst = firstTick_ ? numNewConnection_ * 3 : numNewConnection_;
    firstTick_ = false;
    if ( // for seeder state
        (pieceStorage_->downloadFinished() && btRuntime_->lessThanMaxPeers() &&
         (maxUploadLimit == 0 ||
          stat.calculateUploadSpeed() < maxUploadLimit * 0.8)) ||
        // for leecher state
        (!pieceStorage_->downloadFinished() &&
         (stat.calculateDownloadSpeed() < thresholdSpeed ||
          btRuntime_->lessThanMinPeers()))) {

      int numConnection = 0;
      if (pieceStorage_->downloadFinished()) {
        if (btRuntime_->getMaxPeers() > btRuntime_->getConnections()) {
          numConnection =
              std::min(connBurst, btRuntime_->getMaxPeers() -
                                      btRuntime_->getConnections());
        }
      }
      else {
        numConnection = connBurst;
      }

      makeNewConnections(numConnection);

      // 慢速节点淘汰：连接数已达上限但下载速度仍低于阈值（即想要
      // 更多好源却腾不出名额）时，淘汰长期零下载的最差节点。只在
      // leecher 状态下触发，且跳过 endgame（收尾阶段每个节点都可能是
      // 稀缺块唯一来源，不能乱杀）。
      if (!pieceStorage_->downloadFinished() &&
          !pieceStorage_->isEndGame() &&
          btRuntime_->getConnections() >= btRuntime_->getMaxPeers() &&
          stat.calculateDownloadSpeed() < thresholdSpeed) {
        evictIdlePeer();
      }

      // 行为封禁策略：不依赖连接数上限，在每轮 tick 中检查
      evictZeroProgressPeer();
      evictSnubbingPeer();

      if (btRuntime_->getConnections() == 0 &&
          !pieceStorage_->downloadFinished()) {
        btAnnounce_->overrideMinInterval(BtAnnounce::DEFAULT_ANNOUNCE_INTERVAL);
      }
    }
  }
  e_->addCommand(std::unique_ptr<Command>(this));
  return false;
}

void ActivePeerConnectionCommand::evictIdlePeer()
{
  // 检查自动封禁开关：用户可在偏好设置中关闭此功能
  const auto& opt = requestGroup_->getOption();
  if (opt->defined(PREF_BT_AUTO_BAN_PEER) &&
      opt->get(PREF_BT_AUTO_BAN_PEER) == A2_V_FALSE) {
    return;
  }

  // 节流：最多每 30 秒淘汰一个，避免连续淘汰造成连接抖动。
  if (lastSlowEviction_.difference(global::wallclock()) < 30_s) {
    return;
  }
  auto defaultPeerStorage =
      std::dynamic_pointer_cast<DefaultPeerStorage>(peerStorage_);
  if (!defaultPeerStorage) {
    return;
  }
  const auto& usedPeers = peerStorage_->getUsedPeers();
  const auto now = global::wallclock();
  for (const auto& peer : usedPeers) {
    if (!peer->isActive()) {
      continue;
    }
    // 判据：接入超过 120 秒、当前下载速度为 0。
    // 原为 60 秒，提高到 120 秒以减少误封正常但短暂空闲的节点
    // （如对方正在切换 piece 或拥塞窗口调整）。
    if (peer->calculateDownloadSpeed() != 0) {
      continue;
    }
    if (now.difference(peer->getFirstContactTime()) < 120_s) {
      continue;
    }
    // 封禁 IP：PeerInteractionCommand 每轮执行时会检查 isBadPeer，
    // 命中即关闭该连接并放回节点池；封禁 2~10 分钟后节点可回归。
    defaultPeerStorage->addBadPeer(peer->getIPAddress(), "idle");
    lastSlowEviction_ = now;
    A2_LOG_INFO(fmt("Evicting idle peer %s:%u (0 B/s for >=120s, at peer cap)",
                    peer->getIPAddress().c_str(), peer->getPort()));
    return; // 每轮一个
  }
}

void ActivePeerConnectionCommand::evictZeroProgressPeer()
{
  // 检查开关：用户可在偏好设置中关闭此功能
  const auto& opt = requestGroup_->getOption();
  if (opt->defined(PREF_BT_AUTO_BAN_ZERO_PROGRESS) &&
      opt->get(PREF_BT_AUTO_BAN_ZERO_PROGRESS) == A2_V_FALSE) {
    return;
  }

  // 节流：最多每 60 秒淘汰一个，避免频繁检查
  if (lastZeroProgressEviction_.difference(global::wallclock()) < 60_s) {
    return;
  }

  auto defaultPeerStorage =
      std::dynamic_pointer_cast<DefaultPeerStorage>(peerStorage_);
  if (!defaultPeerStorage) {
    return;
  }

  const auto& usedPeers = peerStorage_->getUsedPeers();
  const auto now = global::wallclock();

  for (const auto& peer : usedPeers) {
    if (!peer->isActive()) {
      continue;
    }

    // 判据：连接超过 180 秒、我们正在向对方上传（uploadSpeed > 0）、
    // 但对方下载完成量始终为 0（零进度）。
    // 180 秒宽限期确保正常节点有足够时间开始下载首个 piece。
    if (now.difference(peer->getFirstContactTime()) < 180_s) {
      continue;
    }

    // 必须是我们正在向其上传的节点
    if (peer->calculateUploadSpeed() == 0) {
      continue;
    }

    // 对方下载完成量为 0 说明它从未从我们这里获得有效数据
    if (peer->getSessionDownloadLength() > 0 ||
        peer->getCompletedLength() > 0) {
      continue;
    }

    // 跳过 seeder（做种者），它们没有下载需求
    if (peer->isSeeder()) {
      continue;
    }

    defaultPeerStorage->addBadPeer(peer->getIPAddress(), "zero_progress");
    lastZeroProgressEviction_ = now;
    A2_LOG_INFO(fmt("Evicting zero-progress peer %s:%u "
                    "(uploading but 0 completed in >=180s)",
                    peer->getIPAddress().c_str(), peer->getPort()));
    return; // 每轮一个
  }
}

void ActivePeerConnectionCommand::evictSnubbingPeer()
{
  // 检查开关：用户可在偏好设置中关闭此功能
  const auto& opt = requestGroup_->getOption();
  if (opt->defined(PREF_BT_AUTO_BAN_SNUBBING) &&
      opt->get(PREF_BT_AUTO_BAN_SNUBBING) == A2_V_FALSE) {
    return;
  }

  // 复用 lastSlowEviction_ 节流，但使用更长的间隔
  if (lastSlowEviction_.difference(global::wallclock()) < 45_s) {
    return;
  }

  auto defaultPeerStorage =
      std::dynamic_pointer_cast<DefaultPeerStorage>(peerStorage_);
  if (!defaultPeerStorage) {
    return;
  }

  const auto& usedPeers = peerStorage_->getUsedPeers();
  const auto now = global::wallclock();

  for (const auto& peer : usedPeers) {
    if (!peer->isActive()) {
      continue;
    }

    // 判据：节点被标记为 snubbing 状态（引擎已有此标志），
    // 且持续超过 90 秒。snubbing 标志由 PeerInteractionCommand
    // 在对方未响应 piece 请求时设置。
    if (!peer->snubbing()) {
      continue;
    }

    if (now.difference(peer->getFirstContactTime()) < 90_s) {
      continue;
    }

    // 下载速度为 0，确认确实未发送数据
    if (peer->calculateDownloadSpeed() != 0) {
      continue;
    }

    defaultPeerStorage->addBadPeer(peer->getIPAddress(), "snubbing");
    lastSlowEviction_ = now;
    A2_LOG_INFO(fmt("Evicting snubbing peer %s:%u (snubbing for >=90s)",
                    peer->getIPAddress().c_str(), peer->getPort()));
    return; // 每轮一个
  }
}

void ActivePeerConnectionCommand::makeNewConnections(int num)
{
  for (; num && peerStorage_->isPeerAvailable(); --num) {
    cuid_t ncuid = e_->newCUID();
    std::shared_ptr<Peer> peer = peerStorage_->checkoutPeer(ncuid);
    // sanity check
    if (!peer) {
      break;
    }
    auto command = make_unique<PeerInitiateConnectionCommand>(
        ncuid, requestGroup_, peer, e_, btRuntime_);
    command->setPeerStorage(peerStorage_);
    command->setPieceStorage(pieceStorage_);
    e_->addCommand(std::move(command));
    A2_LOG_INFO(
        fmt(MSG_CONNECTING_TO_PEER, getCuid(), peer->getIPAddress().c_str()));
  }
}

void ActivePeerConnectionCommand::setBtRuntime(
    const std::shared_ptr<BtRuntime>& btRuntime)
{
  btRuntime_ = btRuntime;
}

void ActivePeerConnectionCommand::setPieceStorage(
    const std::shared_ptr<PieceStorage>& pieceStorage)
{
  pieceStorage_ = pieceStorage;
}

void ActivePeerConnectionCommand::setPeerStorage(
    const std::shared_ptr<PeerStorage>& peerStorage)
{
  peerStorage_ = peerStorage;
}

void ActivePeerConnectionCommand::setBtAnnounce(
    const std::shared_ptr<BtAnnounce>& btAnnounce)
{
  btAnnounce_ = btAnnounce;
}

} // namespace aria2
