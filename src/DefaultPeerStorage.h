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
#ifndef D_DEFAULT_PEER_STORAGE_H
#define D_DEFAULT_PEER_STORAGE_H

#include "PeerStorage.h"

#include <string>
#include <map>

#include "TimerA2.h"

namespace aria2 {

class BtRuntime;
class BtSeederStateChoke;
class BtLeecherStateChoke;
class PieceStorage;

class DefaultPeerStorage : public PeerStorage {
private:
  std::shared_ptr<BtRuntime> btRuntime_;
  std::shared_ptr<PieceStorage> pieceStorage_;
  size_t maxPeerListSize_;

  // This contains ip address and port pair and is used to ensure that
  // no duplicate peers are stored.
  std::set<std::pair<std::string, uint16_t>> uniqPeers_;
  // Unused (not connected) peers, sorted by last added.
  std::deque<std::shared_ptr<Peer>> unusedPeers_;
  // The set of used peers. Some of them are not connected yet. To
  // know it is connected or not, call Peer::isActive().
  PeerSet usedPeers_;

  std::deque<std::shared_ptr<Peer>> droppedPeers_;

  std::unique_ptr<BtSeederStateChoke> seederStateChoke_;
  std::unique_ptr<BtLeecherStateChoke> leecherStateChoke_;

  Timer lastTransferStatMapUpdated_;

  // 封禁来源标记："auto" = 引擎自动封禁（空闲淘汰/坏数据等），
  // "manual" = 用户通过 RPC 手动封禁
  struct BadPeerEntry {
    Timer expireTime;
    std::string source; // "auto" or "manual"
  };
  std::map<std::string, BadPeerEntry> badPeers_;
  Timer lastBadPeerCleaned_;

  bool isPeerAlreadyAdded(const std::shared_ptr<Peer>& peer);
  void addUniqPeer(const std::shared_ptr<Peer>& peer);
  void mergePeerDiscoveryFlags(const std::shared_ptr<Peer>& target,
                               const std::shared_ptr<Peer>& source);
  void addDroppedPeer(const std::shared_ptr<Peer>& peer);
  std::map<std::string, uint32_t> attemptStats_;
  std::map<std::string, uint32_t> failStats_;
  std::map<std::string, uint32_t> tcpFailStats_;
  std::map<std::string, uint32_t> utpFailStats_;
  // Active outgoing/incoming connection count per peer IP, so a single
  // abusive or fast host cannot occupy every connection slot. The map
  // is bounded by the number of distinct IPs in unusedPeers_/usedPeers_.
  std::map<std::string, size_t> ipConnections_;
  // Upper bound of concurrent connections per peer IP.
  static constexpr size_t MAX_CONNECTIONS_PER_IP = 3;
  bool isIpConnectionFull(const std::string& ip) const;
  std::string peerKey(const std::string& ipaddr, uint16_t port) const;
  // Drop all stats for a peer that is being evicted from every list, so
  // the maps stay bounded by the peers we actually track.
  void erasePeerStats(const std::string& ipaddr, uint16_t port);

public:
  DefaultPeerStorage();

  virtual ~DefaultPeerStorage();

  // TODO We need addAndCheckoutPeer for incoming peers
  virtual bool addPeer(const std::shared_ptr<Peer>& peer) CXX11_OVERRIDE;

  virtual size_t countAllPeer() const CXX11_OVERRIDE;

  std::shared_ptr<Peer> getPeer(const std::string& ipaddr, uint16_t port) const;

  virtual void
  addPeer(const std::vector<std::shared_ptr<Peer>>& peers) CXX11_OVERRIDE;

  std::shared_ptr<Peer> addAndCheckoutPeer(const std::shared_ptr<Peer>& peer,
                                           cuid_t cuid) CXX11_OVERRIDE;

  const std::deque<std::shared_ptr<Peer>>& getUnusedPeers();

  virtual const PeerSet& getUsedPeers() CXX11_OVERRIDE;

  virtual const std::deque<std::shared_ptr<Peer>>&
  getDroppedPeers() CXX11_OVERRIDE;

  virtual bool isPeerAvailable() CXX11_OVERRIDE;

  virtual bool isBadPeer(const std::string& ipaddr) CXX11_OVERRIDE;

  virtual void addBadPeer(const std::string& ipaddr) CXX11_OVERRIDE;

  // 手动封禁：由 RPC BanPeer 调用，标记来源为 manual
  void addBadPeerManual(const std::string& ipaddr, const Timer& expireTime);

  void removeBadPeer(const std::string& ipaddr) { badPeers_.erase(ipaddr); }

  const std::map<std::string, BadPeerEntry>& getBadPeers() const { return badPeers_; }
  uint32_t getAttemptCount(const std::string& ipaddr, uint16_t port) const;
  uint32_t getFailCount(const std::string& ipaddr, uint16_t port) const;
  uint32_t getTcpFailCount(const std::string& ipaddr, uint16_t port) const;
  // uTP（BEP 29）连接失败计数——由 peer 命令的异常路径经
  // recordPeerFailure 记录，RPC getPeers 暴露真实数据。
  uint32_t getUtpFailCount(const std::string& ipaddr, uint16_t port) const;
  // 本引擎的 BT 节点传输只有 TCP 与 uTP（uTP 统计见 utpFailStats_），
  // 不存在第三种独立 UDP 传输，该计数恒为 0（RPC schema 兼容）。
  uint32_t getUdpFailCount(const std::string& ipaddr, uint16_t port) const;

  // 连接失败统计入口：peer 命令在异常路径（超时/EOF/协议错误）调用。
  // 按对端传输类型分流：isUtp() → utpFailStats_，否则 tcpFailStats_；
  // 同时累计 failStats_。优雅断开（对端正常关闭）不经过此入口。
  void recordPeerFailure(const std::shared_ptr<Peer>& peer);
  
  // 保存封禁列表到文件
  void saveBannedPeers(const std::string& filename);
  
  // 从文件加载封禁列表
  void loadBannedPeers(const std::string& filename);

  virtual std::shared_ptr<Peer> checkoutPeer(cuid_t cuid) CXX11_OVERRIDE;

  virtual void returnPeer(const std::shared_ptr<Peer>& peer) CXX11_OVERRIDE;

  virtual bool chokeRoundIntervalElapsed() CXX11_OVERRIDE;

  virtual void executeChoke() CXX11_OVERRIDE;

  void deleteUnusedPeer(size_t delSize);

  void onErasingPeer(const std::shared_ptr<Peer>& peer);

  void onReturningPeer(const std::shared_ptr<Peer>& peer);

  void setPieceStorage(const std::shared_ptr<PieceStorage>& pieceStorage);

  void setBtRuntime(const std::shared_ptr<BtRuntime>& btRuntime);

  void setMaxPeerListSize(size_t maxPeerListSize)
  {
    maxPeerListSize_ = maxPeerListSize;
  }
};

} // namespace aria2

#endif // D_DEFAULT_PEER_STORAGE_H
