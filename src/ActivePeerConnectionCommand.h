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
#ifndef D_ACTIVE_PEER_CONNECTION_COMMAND_H
#define D_ACTIVE_PEER_CONNECTION_COMMAND_H

#include "Command.h"

#include <memory>

#include "TimerA2.h"

namespace aria2 {

class RequestGroup;
class DownloadEngine;
class Peer;
class BtRuntime;
class PieceStorage;
class PeerStorage;
class BtAnnounce;

class ActivePeerConnectionCommand : public Command {
private:
  RequestGroup* requestGroup_;
  std::shared_ptr<BtRuntime> btRuntime_;
  std::shared_ptr<PieceStorage> pieceStorage_;
  std::shared_ptr<PeerStorage> peerStorage_;
  std::shared_ptr<BtAnnounce> btAnnounce_;

  std::chrono::seconds interval_;
  DownloadEngine* e_;
  Timer checkPoint_;
  int numNewConnection_; // the number of the connection to establish.
  Timer lastSlowEviction_; // throttle: evict at most one bad peer per 30s
  Timer lastZeroProgressEviction_; // throttle for zero-progress eviction
  bool firstTick_ = true;  // 冷启动突发：首个 tick 一次性发起 3 倍连接
public:
  ActivePeerConnectionCommand(cuid_t cuid, RequestGroup* requestGroup,
                              DownloadEngine* e, std::chrono::seconds interval);

  virtual ~ActivePeerConnectionCommand();

  virtual bool execute() CXX11_OVERRIDE;

  void makeNewConnections(int num);

  // 慢速节点淘汰：连接数达上限且仍需更多源时，封禁"长时间零下载"
  // 的最差节点，为新连接腾名额。每轮最多一个，受 lastSlowEviction_
  // 节流。受 PREF_BT_AUTO_BAN_PEER 开关控制。
  void evictIdlePeer();

  // 零进度淘汰：节点持续向我们请求上传数据（peerInterested && !amChoking），
  // 但其自身下载完成量为 0 且连接时间超过阈值，说明对方可能是吸血
  // (leech) 客户端或异常客户端。受 PREF_BT_AUTO_BAN_ZERO_PROGRESS 开关控制。
  void evictZeroProgressPeer();

  // Snubbing 节点淘汰：节点声明拥有某些 piece 且对我们感兴趣，
  // 但在被 unchoke 后超过 60 秒未发送任何 piece 数据。受
  // PREF_BT_AUTO_BAN_SNUBBING 开关控制。
  void evictSnubbingPeer();

  void setNumNewConnection(int numNewConnection)
  {
    numNewConnection_ = numNewConnection;
  }

  void setBtRuntime(const std::shared_ptr<BtRuntime>& btRuntime);

  void setPieceStorage(const std::shared_ptr<PieceStorage>& pieceStorage);

  void setPeerStorage(const std::shared_ptr<PeerStorage>& peerStorage);

  void setBtAnnounce(const std::shared_ptr<BtAnnounce>& btAnnounce);
};

} // namespace aria2

#endif // D_ACTIVE_PEER_CONNECTION_COMMAND_H
