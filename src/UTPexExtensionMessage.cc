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
#include "UTPexExtensionMessage.h"
#include "Peer.h"
#include "util.h"
#include "bittorrent_helper.h"
#include "PeerStorage.h"
#include "DlAbortEx.h"
#include "message.h"
#include "fmt.h"
#include "bencode2.h"
#include "a2functional.h"
#include "wallclock.h"

namespace aria2 {

namespace {

// This is the hard limit of the number of "fresh peer" and "dropped
// peer".  This number is treated as the sum of IPv4 and IPv6 peers.
const size_t DEFAULT_MAX_FRESH_PEER = 120;
const size_t DEFAULT_MAX_DROPPED_PEER = 120;

} // namespace

const char UTPexExtensionMessage::EXTENSION_NAME[] = "ut_pex";

constexpr std::chrono::seconds UTPexExtensionMessage::DEFAULT_INTERVAL;

UTPexExtensionMessage::UTPexExtensionMessage(uint8_t extensionMessageID)
    : extensionMessageID_{extensionMessageID},
      peerStorage_{nullptr},
      interval_{DEFAULT_INTERVAL},
      maxFreshPeer_{DEFAULT_MAX_FRESH_PEER},
      maxDroppedPeer_{DEFAULT_MAX_DROPPED_PEER}
{
}

std::string UTPexExtensionMessage::getPayload()
{
  auto freshPeerPair = createCompactPeerListAndFlag(freshPeers_);
  auto droppedPeerPair = createCompactPeerListAndFlag(droppedPeers_);
  Dict dict;
  if (!freshPeerPair.first.first.empty()) {
    dict.put("added", freshPeerPair.first.first);
    dict.put("added.f", freshPeerPair.first.second);
  }
  if (!droppedPeerPair.first.first.empty()) {
    dict.put("dropped", droppedPeerPair.first.first);
  }
  if (!freshPeerPair.second.first.empty()) {
    dict.put("added6", freshPeerPair.second.first);
    dict.put("added6.f", freshPeerPair.second.second);
  }
  if (!droppedPeerPair.second.first.empty()) {
    dict.put("dropped6", droppedPeerPair.second.first);
  }

  return bencode2::encode(&dict);
}

std::pair<std::pair<std::string, std::string>,
          std::pair<std::string, std::string>>
UTPexExtensionMessage::createCompactPeerListAndFlag(
    const std::vector<std::shared_ptr<Peer>>& peers)
{
  std::string addrstring;
  std::string flagstring;
  std::string addrstring6;
  std::string flagstring6;
  for (auto itr = std::begin(peers), eoi = std::end(peers); itr != eoi; ++itr) {
    unsigned char compact[COMPACT_LEN_IPV6];
    int compactlen = bittorrent::packcompact(compact, (*itr)->getIPAddress(),
                                             (*itr)->getPort());
    // BEP 11 flags: 0x01 = prefers encryption，0x02 = seed/upload_only，
    // 0x04 = supports uTP。广播 uTP 能力必须用 0x04 位——此前误用
    // 0x01（加密位）会污染 PEX 网络：对端会把我们通告的 peer 误解为
    // "偏好加密"，而真正的 uTP 能力从未传播出去。
    unsigned char flags =
        ((*itr)->isSeeder() ? 0x02u : 0x00u) |
        ((*itr)->isUtpCapable() ? 0x04u : 0x00u);
    if (compactlen == COMPACT_LEN_IPV4) {
      addrstring.append(&compact[0], &compact[compactlen]);
      flagstring += static_cast<char>(flags);
    }
    else if (compactlen == COMPACT_LEN_IPV6) {
      addrstring6.append(&compact[0], &compact[compactlen]);
      flagstring6 += static_cast<char>(flags);
    }
  }
  return std::make_pair(
      std::make_pair(std::move(addrstring), std::move(flagstring)),
      std::make_pair(std::move(addrstring6), std::move(flagstring6)));
}

std::string UTPexExtensionMessage::toString() const
{
  return fmt("ut_pex added=%lu, dropped=%lu",
             static_cast<unsigned long>(freshPeers_.size()),
             static_cast<unsigned long>(droppedPeers_.size()));
}

void UTPexExtensionMessage::doReceivedAction()
{
  peerStorage_->addPeer(freshPeers_);
  peerStorage_->addPeer(droppedPeers_);
}

bool UTPexExtensionMessage::addFreshPeer(const std::shared_ptr<Peer>& peer)
{
  if (!peer->isIncomingPeer() &&
      peer->getFirstContactTime().difference(global::wallclock()) < interval_) {
    freshPeers_.push_back(peer);
    return true;
  }
  else {
    return false;
  }
}

const std::vector<std::shared_ptr<Peer>>&
UTPexExtensionMessage::getFreshPeers() const
{
  return freshPeers_;
}

bool UTPexExtensionMessage::freshPeersAreFull() const
{
  return freshPeers_.size() >= maxFreshPeer_;
}

bool UTPexExtensionMessage::addDroppedPeer(const std::shared_ptr<Peer>& peer)
{
  if (!peer->isIncomingPeer() &&
      peer->getDropStartTime().difference(global::wallclock()) < interval_) {
    droppedPeers_.push_back(peer);
    return true;
  }
  else {
    return false;
  }
}

const std::vector<std::shared_ptr<Peer>>&
UTPexExtensionMessage::getDroppedPeers() const
{
  return droppedPeers_;
}

bool UTPexExtensionMessage::droppedPeersAreFull() const
{
  return droppedPeers_.size() >= maxDroppedPeer_;
}

void UTPexExtensionMessage::setMaxFreshPeer(size_t maxFreshPeer)
{
  maxFreshPeer_ = maxFreshPeer;
}

void UTPexExtensionMessage::setMaxDroppedPeer(size_t maxDroppedPeer)
{
  maxDroppedPeer_ = maxDroppedPeer;
}

void UTPexExtensionMessage::setPeerStorage(PeerStorage* peerStorage)
{
  peerStorage_ = peerStorage;
}

std::unique_ptr<UTPexExtensionMessage>
UTPexExtensionMessage::create(const unsigned char* data, size_t len)
{
  if (len < 1) {
    throw DL_ABORT_EX(fmt(MSG_TOO_SMALL_PAYLOAD_SIZE, EXTENSION_NAME,
                          static_cast<unsigned long>(len)));
  }
  auto msg = make_unique<UTPexExtensionMessage>(*data);

  auto decoded = bencode2::decode(data + 1, len - 1);
  const Dict* dict = downcast<Dict>(decoded);
  if (dict) {
    const String* added = downcast<String>(dict->get("added"));
    if (added) {
      bittorrent::extractPeer(added, AF_INET,
                              std::back_inserter(msg->freshPeers_));
    }
    // IPv4 节点数量：added6 的标志位要映射到其后的偏移位置。
    const size_t v4Count = msg->freshPeers_.size();
    const String* dropped = downcast<String>(dict->get("dropped"));
    if (dropped) {
      bittorrent::extractPeer(dropped, AF_INET,
                              std::back_inserter(msg->droppedPeers_));
    }
    const String* added6 = downcast<String>(dict->get("added6"));
    if (added6) {
      bittorrent::extractPeer(added6, AF_INET6,
                              std::back_inserter(msg->freshPeers_));
    }
    const String* dropped6 = downcast<String>(dict->get("dropped6"));
    if (dropped6) {
      bittorrent::extractPeer(dropped6, AF_INET6,
                              std::back_inserter(msg->droppedPeers_));
    }
    // BEP 11 flags: added.f / added6.f 每字节对应 added/added6 中同一
    // 序号的 peer：0x01 = prefers encryption，0x02 = seed/upload_only，
    // 0x04 = supports uTP，0x08 = ut_holepunch。uTP 能力位是 0x04——
    // 此前误用 0x01（加密位，现代客户端几乎全设置），导致对大量仅
    // 支持加密而不支持 uTP 的 peer 发起注定失败的 uTP 连接（SYN 无
    // 响应，~15s 死链超时，表现为"uTP 节点无客户端、无速度"）。
    // 解析后标记对端 uTP 能力，供出站连接决策与 PEX 广播。
    // 字节数不足/多余按 min 截断容错。
    const String* addedF = downcast<String>(dict->get("added.f"));
    if (addedF && !addedF->s().empty()) {
      const size_t n = std::min(addedF->s().size(), v4Count);
      for (size_t i = 0; i < n; ++i) {
        if (msg->freshPeers_[i] &&
            (static_cast<unsigned char>(addedF->s()[i]) & 0x04u)) {
          msg->freshPeers_[i]->setUtpCapable(true);
        }
      }
    }
    const String* added6F = downcast<String>(dict->get("added6.f"));
    if (added6F && !added6F->s().empty()) {
      const size_t n = std::min(added6F->s().size(),
                                msg->freshPeers_.size() - v4Count);
      for (size_t i = 0; i < n; ++i) {
        auto& peer = msg->freshPeers_[v4Count + i];
        if (peer &&
            (static_cast<unsigned char>(added6F->s()[i]) & 0x04u)) {
          peer->setUtpCapable(true);
        }
      }
    }
  }
  for (auto& peer : msg->freshPeers_) {
    if (peer) {
      peer->setFromPEX(true);
    }
  }
  for (auto& peer : msg->droppedPeers_) {
    if (peer) {
      peer->setFromPEX(true);
    }
  }
  return msg;
}

} // namespace aria2
