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
#include "DefaultPeerStorage.h"

#include <algorithm>
#include <fstream>
#include <sstream>

#include "LogFactory.h"
#include "Logger.h"
#include "message.h"
#include "Peer.h"
#include "BtRuntime.h"
#include "BtSeederStateChoke.h"
#include "BtLeecherStateChoke.h"
#include "PieceStorage.h"
#include "wallclock.h"
#include "a2functional.h"
#include "fmt.h"
#include "SimpleRandomizer.h"

namespace aria2 {

namespace {

const size_t MAX_PEER_LIST_SIZE = 512;

} // namespace

DefaultPeerStorage::DefaultPeerStorage()
    : maxPeerListSize_(MAX_PEER_LIST_SIZE),
      seederStateChoke_(make_unique<BtSeederStateChoke>()),
      leecherStateChoke_(make_unique<BtLeecherStateChoke>()),
      lastTransferStatMapUpdated_(Timer::zero())
{
}

DefaultPeerStorage::~DefaultPeerStorage()
{
  assert(uniqPeers_.size() == unusedPeers_.size() + usedPeers_.size());
}

std::string DefaultPeerStorage::peerKey(const std::string& ipaddr, uint16_t port) const
{
  return fmt("%s:%u", ipaddr.c_str(), port);
}

void DefaultPeerStorage::erasePeerStats(const std::string& ipaddr, uint16_t port)
{
  const auto key = peerKey(ipaddr, port);
  attemptStats_.erase(key);
  failStats_.erase(key);
  tcpFailStats_.erase(key);
  utpFailStats_.erase(key);
}

uint32_t DefaultPeerStorage::getAttemptCount(const std::string& ipaddr, uint16_t port) const
{
  const auto key = peerKey(ipaddr, port);
  auto it = attemptStats_.find(key);
  return it == attemptStats_.end() ? 0 : it->second;
}

uint32_t DefaultPeerStorage::getFailCount(const std::string& ipaddr, uint16_t port) const
{
  const auto key = peerKey(ipaddr, port);
  auto it = failStats_.find(key);
  return it == failStats_.end() ? 0 : it->second;
}

uint32_t DefaultPeerStorage::getTcpFailCount(const std::string& ipaddr, uint16_t port) const
{
  const auto key = peerKey(ipaddr, port);
  auto it = tcpFailStats_.find(key);
  return it == tcpFailStats_.end() ? 0 : it->second;
}

uint32_t DefaultPeerStorage::getUtpFailCount(const std::string& ipaddr,
                                             uint16_t port) const
{
  const auto key = peerKey(ipaddr, port);
  auto it = utpFailStats_.find(key);
  return it == utpFailStats_.end() ? 0 : it->second;
}

uint32_t DefaultPeerStorage::getUdpFailCount(const std::string&, uint16_t) const
{
  // 本引擎 BT 节点传输仅 TCP 与 uTP；无独立 UDP 传输，恒为 0。
  return 0;
}

void DefaultPeerStorage::recordPeerFailure(const std::shared_ptr<Peer>& peer)
{
  if (!peer) {
    return;
  }
  const auto key = peerKey(peer->getIPAddress(), peer->getOrigPort());
  failStats_[key] += 1;
  if (peer->isUtp()) {
    utpFailStats_[key] += 1;
  }
  else {
    tcpFailStats_[key] += 1;
  }
}

size_t DefaultPeerStorage::countAllPeer() const
{
  return unusedPeers_.size() + usedPeers_.size();
}

bool DefaultPeerStorage::isPeerAlreadyAdded(const std::shared_ptr<Peer>& peer)
{
  return uniqPeers_.count(
      std::make_pair(peer->getIPAddress(), peer->getOrigPort()));
}

void DefaultPeerStorage::addUniqPeer(const std::shared_ptr<Peer>& peer)
{
  uniqPeers_.insert(std::make_pair(peer->getIPAddress(), peer->getOrigPort()));
}

void DefaultPeerStorage::mergePeerDiscoveryFlags(
    const std::shared_ptr<Peer>& target, const std::shared_ptr<Peer>& source)
{
  if (!target || !source) {
    return;
  }
  if (source->isFromDHT()) {
    target->setFromDHT(true);
  }
  if (source->isFromPEX()) {
    target->setFromPEX(true);
  }
  if (source->isLocalPeer()) {
    target->setLocalPeer(true);
  }
}

bool DefaultPeerStorage::addPeer(const std::shared_ptr<Peer>& peer)
{
  if (unusedPeers_.size() >= maxPeerListSize_) {
    A2_LOG_DEBUG(fmt("Adding %s:%u is rejected, since unused peer list is full "
                     "(%lu peers > %lu)",
                     peer->getIPAddress().c_str(), peer->getPort(),
                     static_cast<unsigned long>(unusedPeers_.size()),
                     static_cast<unsigned long>(maxPeerListSize_)));
    return false;
  }
  if (isPeerAlreadyAdded(peer)) {
    auto existing = getPeer(peer->getIPAddress(), peer->getOrigPort());
    mergePeerDiscoveryFlags(existing, peer);
    A2_LOG_DEBUG(fmt("Adding %s:%u is rejected because it has been already"
                     " added.",
                     peer->getIPAddress().c_str(), peer->getPort()));
    return false;
  }
  if (isBadPeer(peer->getIPAddress())) {
    A2_LOG_DEBUG(fmt("Adding %s:%u is rejected because it is marked bad.",
                     peer->getIPAddress().c_str(), peer->getPort()));
    return false;
  }
  const size_t peerListSize = unusedPeers_.size();
  if (peerListSize >= maxPeerListSize_) {
    deleteUnusedPeer(peerListSize - maxPeerListSize_ + 1);
  }
  unusedPeers_.push_back(peer);
  addUniqPeer(peer);
  A2_LOG_DEBUG(fmt("Now unused peer list contains %lu peers",
                   static_cast<unsigned long>(unusedPeers_.size())));
  return true;
}

void DefaultPeerStorage::addPeer(
    const std::vector<std::shared_ptr<Peer>>& peers)
{
  if (unusedPeers_.size() < maxPeerListSize_) {
    for (auto& peer : peers) {
      if (isPeerAlreadyAdded(peer)) {
        auto existing = getPeer(peer->getIPAddress(), peer->getOrigPort());
        mergePeerDiscoveryFlags(existing, peer);
        A2_LOG_DEBUG(fmt("Adding %s:%u is rejected because it has been already"
                         " added.",
                         peer->getIPAddress().c_str(), peer->getPort()));
        continue;
      }
      else if (isBadPeer(peer->getIPAddress())) {
        A2_LOG_DEBUG(fmt("Adding %s:%u is rejected because it is marked bad.",
                         peer->getIPAddress().c_str(), peer->getPort()));
        continue;
      }
      else {
        A2_LOG_DEBUG(fmt(MSG_ADDING_PEER, peer->getIPAddress().c_str(),
                         peer->getPort()));
      }
      unusedPeers_.push_back(peer);
      addUniqPeer(peer);
    }
  }
  else {
    for (auto& peer : peers) {
      A2_LOG_DEBUG(
          fmt("Adding %s:%u is rejected, since unused peer list is full "
              "(%lu peers > %lu)",
              peer->getIPAddress().c_str(), peer->getPort(),
              static_cast<unsigned long>(unusedPeers_.size()),
              static_cast<unsigned long>(maxPeerListSize_)));
    }
  }
  const size_t peerListSize = unusedPeers_.size();
  if (peerListSize > maxPeerListSize_) {
    deleteUnusedPeer(peerListSize - maxPeerListSize_);
  }
  A2_LOG_DEBUG(fmt("Now unused peer list contains %lu peers",
                   static_cast<unsigned long>(unusedPeers_.size())));
}

std::shared_ptr<Peer>
DefaultPeerStorage::addAndCheckoutPeer(const std::shared_ptr<Peer>& peer,
                                       cuid_t cuid)
{
  // 检查是否是被封禁的IP
  if (isBadPeer(peer->getIPAddress())) {
    A2_LOG_DEBUG(fmt("Rejecting incoming connection from %s:%u because it is marked bad.",
                     peer->getIPAddress().c_str(), peer->getPort()));
    return nullptr;
  }

  if (isPeerAlreadyAdded(peer)) {
    auto it = std::find_if(std::begin(unusedPeers_), std::end(unusedPeers_),
                           [&peer](const std::shared_ptr<Peer>& p) {
                             return p->getIPAddress() == peer->getIPAddress() &&
                                     p->getOrigPort() == peer->getOrigPort();
                           });
    if (it == std::end(unusedPeers_)) {
      return nullptr;
    }

    mergePeerDiscoveryFlags(peer, *it);
    unusedPeers_.erase(it);
  }
  else {
    addUniqPeer(peer);
  }

  unusedPeers_.push_front(peer);

  return checkoutPeer(cuid);
}

std::shared_ptr<Peer> DefaultPeerStorage::getPeer(const std::string& ipaddr,
                                                  uint16_t port) const
{
  for (const auto& peer : unusedPeers_) {
    if (peer->getIPAddress() == ipaddr && peer->getOrigPort() == port) {
      return peer;
    }
  }
  for (const auto& peer : usedPeers_) {
    if (peer->getIPAddress() == ipaddr && peer->getOrigPort() == port) {
      return peer;
    }
  }
  return nullptr;
}

void DefaultPeerStorage::addDroppedPeer(const std::shared_ptr<Peer>& peer)
{
  // Make sure that no duplicated peer exists in droppedPeers_. If
  // exists, erase older one.
  for (auto i = std::begin(droppedPeers_), eoi = std::end(droppedPeers_);
       i != eoi; ++i) {
    if ((*i)->getIPAddress() == peer->getIPAddress() &&
        (*i)->getPort() == peer->getPort()) {
      droppedPeers_.erase(i);
      break;
    }
  }
  droppedPeers_.push_front(peer);
  if (droppedPeers_.size() > 50) {
    // The evicted peer is gone from every list — drop its stats too.
    const auto& evicted = droppedPeers_.back();
    erasePeerStats(evicted->getIPAddress(), evicted->getOrigPort());
    droppedPeers_.pop_back();
  }
}

const std::deque<std::shared_ptr<Peer>>& DefaultPeerStorage::getUnusedPeers()
{
  return unusedPeers_;
}

const PeerSet& DefaultPeerStorage::getUsedPeers() { return usedPeers_; }

const std::deque<std::shared_ptr<Peer>>& DefaultPeerStorage::getDroppedPeers()
{
  return droppedPeers_;
}

bool DefaultPeerStorage::isPeerAvailable() { return !unusedPeers_.empty(); }

bool DefaultPeerStorage::isBadPeer(const std::string& ipaddr)
{
  auto i = badPeers_.find(ipaddr);
  if (i == std::end(badPeers_)) {
    return false;
  }

  if ((*i).second.expireTime <= global::wallclock()) {
    badPeers_.erase(i);
    return false;
  }

  return true;
}

void DefaultPeerStorage::addBadPeer(const std::string& ipaddr)
{
  if (lastBadPeerCleaned_.difference(global::wallclock()) >= 1_h) {
    for (auto i = std::begin(badPeers_); i != std::end(badPeers_);) {
      if ((*i).second.expireTime <= global::wallclock()) {
        A2_LOG_DEBUG(fmt("Purge %s from bad peer", (*i).first.c_str()));
        badPeers_.erase(i++);
        // badPeers_.end() will not be invalidated.
      }
      else {
        ++i;
      }
    }
    lastBadPeerCleaned_ = global::wallclock();
  }
  A2_LOG_DEBUG(fmt("Added %s as bad peer (auto)", ipaddr.c_str()));
  // We use variable timeout to avoid many bad peers wake up at once.
  auto t = global::wallclock();
  t.advance(std::chrono::seconds(
      std::max(SimpleRandomizer::getInstance()->getRandomNumber(601), 120L)));

  badPeers_[ipaddr] = BadPeerEntry{std::move(t), "auto"};
}

void DefaultPeerStorage::addBadPeerManual(const std::string& ipaddr,
                                         const Timer& expireTime)
{
  // 手动封禁不清理过期项（BanPeerRpcMethod 已自行处理累加逻辑）
  badPeers_[ipaddr] = BadPeerEntry{expireTime, "manual"};
}

void DefaultPeerStorage::deleteUnusedPeer(size_t delSize)
{
  for (; delSize > 0 && !unusedPeers_.empty(); --delSize) {
    auto& peer = unusedPeers_.back();
    onErasingPeer(peer);
    // Permanently evicted without ever being used — its stats are no
    // longer reachable via RPC; drop them to keep the maps bounded.
    erasePeerStats(peer->getIPAddress(), peer->getOrigPort());
    A2_LOG_DEBUG(fmt("Remove peer %s:%u", peer->getIPAddress().c_str(),
                     peer->getOrigPort()));
    unusedPeers_.pop_back();
  }
}

bool DefaultPeerStorage::isIpConnectionFull(const std::string& ip) const
{
  auto it = ipConnections_.find(ip);
  return it != ipConnections_.end() && it->second >= MAX_CONNECTIONS_PER_IP;
}

std::shared_ptr<Peer> DefaultPeerStorage::checkoutPeer(cuid_t cuid)
{
  if (!isPeerAvailable()) {
    return nullptr;
  }
  
  // 跳过被封禁的peer；跳过已达单 IP 连接上限的 peer（轮转到队尾，
  // 等现有连接释放后再试，而不是丢弃）。
  size_t scanned = 0;
  const size_t initialCount = unusedPeers_.size();
  while (!unusedPeers_.empty() && scanned < initialCount) {
    auto peer = unusedPeers_.front();
    unusedPeers_.pop_front();
    ++scanned;
    
    // 检查是否被封禁
    if (isBadPeer(peer->getIPAddress())) {
      A2_LOG_DEBUG(fmt("Skipping peer %s:%u because it is marked bad.",
                       peer->getIPAddress().c_str(), peer->getPort()));
      onErasingPeer(peer);
      continue;
    }
    
    // 单 IP 并发连接上限：防止一个 IP 占满所有连接槽位
    if (isIpConnectionFull(peer->getIPAddress())) {
      A2_LOG_DEBUG(fmt("Deferring peer %s:%u: IP at connection cap",
                       peer->getIPAddress().c_str(), peer->getPort()));
      unusedPeers_.push_back(peer);
      continue;
    }
    
    if (peer->usedBy() != 0) {
      A2_LOG_WARN(fmt("CUID#%" PRId64 " is already set for peer %s:%u",
                      peer->usedBy(), peer->getIPAddress().c_str(),
                      peer->getOrigPort()));
    }
    
    // 如果peer的firstContactTime是零（被重置过），说明这是重新连接
    // 需要重新设置连接时间
    if (peer->getFirstContactTime().isZero()) {
      peer->setFirstContactTime(global::wallclock());
    }
    
    peer->usedBy(cuid);
    usedPeers_.insert(peer);
    ipConnections_[peer->getIPAddress()] += 1;
    const auto key = peerKey(peer->getIPAddress(), peer->getOrigPort());
    attemptStats_[key] += 1;
    A2_LOG_DEBUG(fmt("Checkout peer %s:%u to CUID#%" PRId64,
                     peer->getIPAddress().c_str(), peer->getOrigPort(),
                     peer->usedBy()));
    return peer;
  }
  
  return nullptr;
}

void DefaultPeerStorage::onErasingPeer(const std::shared_ptr<Peer>& peer)
{
  uniqPeers_.erase(std::make_pair(peer->getIPAddress(), peer->getOrigPort()));
}

void DefaultPeerStorage::onReturningPeer(const std::shared_ptr<Peer>& peer)
{
  // Release the per-IP connection slot for this peer.
  auto it = ipConnections_.find(peer->getIPAddress());
  if (it != ipConnections_.end()) {
    if (it->second > 1) {
      --it->second;
    }
    else {
      ipConnections_.erase(it);
    }
  }

  if (peer->isActive()) {
    if (peer->isDisconnectedGracefully() && !peer->isIncomingPeer()) {
      // 节点断开连接时，重置连接时间
      // 这样下次连接时，连接时间会从0开始
      peer->setFirstContactTime(Timer::zero());
      peer->startDrop();
      addDroppedPeer(peer);
      // 优雅断连（对端正常关闭）不是连接失败，不计入
      // failStats_/tcpFailStats_——否则 RPC 暴露的失败计数虚高，
      // 且影响后续节点选择评分。
    }
    // Execute choking algorithm if unchoked and interested peer is
    // disconnected.
    if (!peer->amChoking() && peer->peerInterested()) {
      executeChoke();
    }
  }
  peer->usedBy(0);
}

void DefaultPeerStorage::returnPeer(const std::shared_ptr<Peer>& peer)
{
  A2_LOG_DEBUG(fmt("Peer %s:%u returned from CUID#%" PRId64,
                   peer->getIPAddress().c_str(), peer->getOrigPort(),
                   peer->usedBy()));
  if (usedPeers_.erase(peer)) {
    onReturningPeer(peer);
    onErasingPeer(peer);
  }
  else {
    A2_LOG_WARN(fmt("Cannot find peer %s:%u in usedPeers_",
                    peer->getIPAddress().c_str(), peer->getOrigPort()));
  }
}

bool DefaultPeerStorage::chokeRoundIntervalElapsed()
{
  constexpr auto CHOKE_ROUND_INTERVAL = 10_s;

  if (pieceStorage_->downloadFinished()) {
    return seederStateChoke_->getLastRound().difference(global::wallclock()) >=
           CHOKE_ROUND_INTERVAL;
  }

  return leecherStateChoke_->getLastRound().difference(global::wallclock()) >=
         CHOKE_ROUND_INTERVAL;
}

void DefaultPeerStorage::executeChoke()
{
  if (pieceStorage_->downloadFinished()) {
    return seederStateChoke_->executeChoke(usedPeers_);
  }
  else {
    return leecherStateChoke_->executeChoke(usedPeers_);
  }
}

void DefaultPeerStorage::setPieceStorage(
    const std::shared_ptr<PieceStorage>& ps)
{
  pieceStorage_ = ps;
}

void DefaultPeerStorage::setBtRuntime(
    const std::shared_ptr<BtRuntime>& btRuntime)
{
  btRuntime_ = btRuntime;
}

void DefaultPeerStorage::saveBannedPeers(const std::string& filename)
{
  try {
    // 使用文本模式打开文件（不使用binary模式）
    std::ofstream ofs(filename);
    if (!ofs) {
      A2_LOG_WARN(fmt("Failed to open banned peers file for writing: %s", filename.c_str()));
      return;
    }
    
    // 写入版本号，使用std::endl确保换行和刷新
    ofs << "BANNED_PEERS_V1" << std::endl;
    
    // 写入封禁列表
    auto now = global::wallclock();
    int savedCount = 0;
    
    A2_LOG_DEBUG(fmt("Saving banned peers: badPeers_ has %zu entries", badPeers_.size()));
    
    for (const auto& entry : badPeers_) {
      const std::string& ip = entry.first;
      const Timer& expireTime = entry.second.expireTime;
      const std::string& source = entry.second.source;
      
      // 只保存未过期的封禁
      if (expireTime > now) {
        // 计算剩余时间（秒）- 注意：expireTime在未来，所以是 expireTime - now
        // 使用 now.difference(expireTime) 来计算从now到expireTime的时间差
        auto remaining = now.difference(expireTime);
        int64_t remainingSeconds = std::chrono::duration_cast<std::chrono::seconds>(remaining).count();
        
        A2_LOG_DEBUG(fmt("Checking peer %s: remaining=%ld seconds, source=%s", 
                         ip.c_str(), static_cast<long>(remainingSeconds), source.c_str()));
        
        // 再次检查剩余时间是否大于0
        if (remainingSeconds > 0) {
          // 格式：IP 剩余秒数 来源，使用std::endl确保换行
          ofs << ip << " " << remainingSeconds << " " << source << std::endl;
          savedCount++;
          A2_LOG_INFO(fmt("Saved banned peer %s with %ld seconds remaining", 
                          ip.c_str(), static_cast<long>(remainingSeconds)));
        } else {
          A2_LOG_DEBUG(fmt("Skipping peer %s with non-positive remaining time: %ld seconds", 
                           ip.c_str(), static_cast<long>(remainingSeconds)));
        }
      } else {
        A2_LOG_DEBUG(fmt("Skipping expired ban for %s (expireTime <= now)", ip.c_str()));
      }
    }
    
    ofs.close();
    A2_LOG_INFO(fmt("Saved %d banned peers (out of %zu total) to %s", 
                    savedCount, badPeers_.size(), filename.c_str()));
  } catch (const std::exception& e) {
    A2_LOG_WARN(fmt("Failed to save banned peers: %s", e.what()));
  }
}

void DefaultPeerStorage::loadBannedPeers(const std::string& filename)
{
  try {
    std::ifstream ifs(filename);
    if (!ifs) {
      // 文件不存在是正常的（首次运行）
      A2_LOG_DEBUG(fmt("Banned peers file not found: %s (this is normal for first run)", filename.c_str()));
      return;
    }
    
    A2_LOG_DEBUG(fmt("Opening banned peers file: %s", filename.c_str()));
    
    std::string version;
    std::getline(ifs, version);
    
    A2_LOG_DEBUG(fmt("Read version line: '%s' (length=%zu)", version.c_str(), version.size()));
    
    // 去除可能的回车符（Windows文本文件）
    if (!version.empty() && version.back() == '\r') {
      version.pop_back();
      A2_LOG_DEBUG(fmt("Removed trailing \\r, version is now: '%s'", version.c_str()));
    }
    
    if (version != "BANNED_PEERS_V1") {
      A2_LOG_WARN(fmt("Unknown banned peers file version: '%s' (expected 'BANNED_PEERS_V1')", version.c_str()));
      return;
    }
    
    auto now = global::wallclock();
    int loadedCount = 0;
    int skippedCount = 0;
    int lineNumber = 1;
    
    std::string line;
    while (std::getline(ifs, line)) {
      lineNumber++;
      
      // 去除可能的回车符
      if (!line.empty() && line.back() == '\r') {
        line.pop_back();
      }
      
      // 跳过空行
      if (line.empty()) {
        A2_LOG_DEBUG(fmt("Line %d: empty line, skipping", lineNumber));
        continue;
      }
      
      A2_LOG_DEBUG(fmt("Line %d: '%s'", lineNumber, line.c_str()));
      
      std::istringstream iss(line);
      std::string ip;
      int64_t remainingSeconds;
      
      std::string source;
      if (iss >> ip >> remainingSeconds >> source) {
        // V2 格式：IP 剩余秒数 来源
        if (source != "auto" && source != "manual") {
          source = "auto"; // 默认值
        }
      } else {
        // 回退到 V1 格式：IP 剩余秒数（无来源字段）
        std::istringstream iss2(line);
        if (!(iss2 >> ip >> remainingSeconds)) {
          A2_LOG_WARN(fmt("Line %d: failed to parse line: '%s'", lineNumber, line.c_str()));
          continue;
        }
        source = "auto"; // 旧格式默认为自动
      }
      
      A2_LOG_DEBUG(fmt("Line %d: parsed IP='%s', remaining=%ld seconds, source=%s", 
                       lineNumber, ip.c_str(), static_cast<long>(remainingSeconds), source.c_str()));
      
      if (remainingSeconds > 0) {
        Timer expireTime = now;
        expireTime.advance(std::chrono::seconds(remainingSeconds));
        badPeers_[ip] = BadPeerEntry{std::move(expireTime), source};
        loadedCount++;
        A2_LOG_INFO(fmt("Loaded banned peer %s with %ld seconds remaining (source=%s)", 
                        ip.c_str(), static_cast<long>(remainingSeconds), source.c_str()));
      } else {
        skippedCount++;
        A2_LOG_DEBUG(fmt("Skipped expired ban for %s (remaining: %ld)", 
                         ip.c_str(), static_cast<long>(remainingSeconds)));
      }
    }
    
    ifs.close();
    A2_LOG_INFO(fmt("Loaded %d banned peers from %s (skipped %d expired)", 
                    loadedCount, filename.c_str(), skippedCount));
  } catch (const std::exception& e) {
    A2_LOG_WARN(fmt("Failed to load banned peers: %s", e.what()));
  }
}

} // namespace aria2
