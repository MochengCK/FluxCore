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
#include "DefaultBtAnnounce.h"
#include "LogFactory.h"
#include "Logger.h"
#include "util.h"
#include "prefs.h"
#include "DlAbortEx.h"
#include "message.h"
#include "SimpleRandomizer.h"
#include "DownloadContext.h"
#include "PieceStorage.h"
#include "BtRuntime.h"
#include "PeerStorage.h"
#include "Peer.h"
#include "Option.h"
#include "fmt.h"
#include "A2STR.h"
#include "bencode2.h"
#include "bittorrent_helper.h"
#include "wallclock.h"
#include "uri.h"
#include "UDPTrackerRequest.h"
#include "SocketCore.h"

namespace aria2 {

DefaultBtAnnounce::DefaultBtAnnounce(DownloadContext* downloadContext,
                                     const Option* option)
    : downloadContext_{downloadContext},
      trackers_(0),
      prevAnnounceTimer_(Timer::zero()),
      interval_(DEFAULT_ANNOUNCE_INTERVAL),
      minInterval_(DEFAULT_ANNOUNCE_INTERVAL),
      userDefinedInterval_(0_s),
      complete_(0),
      incomplete_(0),
      announceList_(bittorrent::getTorrentAttrs(downloadContext)->announceList),
      option_(option),
      randomizer_(SimpleRandomizer::getInstance().get()),
      tcpPort_(0)
{
  // Pre-initialize trackerStatsMap_ with all tracker URLs from announce list
  // so that all trackers show meaningful initial status instead of "pending"
  auto torrentAttrs = bittorrent::getTorrentAttrs(downloadContext);
  if (torrentAttrs) {
    for (const auto& tier : torrentAttrs->announceList) {
      for (const auto& url : tier) {
        trackerStatsMap_[url] = TrackerStats();
      }
    }
  }
}

DefaultBtAnnounce::~DefaultBtAnnounce() = default;

bool DefaultBtAnnounce::isDefaultAnnounceReady()
{
  return (trackers_ == 0 &&
          prevAnnounceTimer_.difference(global::wallclock()) >=
              (userDefinedInterval_.count() == 0 ? minInterval_
                                                 : userDefinedInterval_) &&
          !announceList_.allTiersFailed());
}

bool DefaultBtAnnounce::isStoppedAnnounceReady()
{
  return (trackers_ == 0 && btRuntime_->isHalt() &&
          announceList_.countStoppedAllowedTier());
}

bool DefaultBtAnnounce::isCompletedAnnounceReady()
{
  return (trackers_ == 0 && pieceStorage_->allDownloadFinished() &&
          announceList_.countCompletedAllowedTier());
}

bool DefaultBtAnnounce::isAnnounceReady()
{
  return isStoppedAnnounceReady() || isCompletedAnnounceReady() ||
         isDefaultAnnounceReady();
}

namespace {
bool uriHasQuery(const std::string& uri)
{
  uri_split_result us;
  if (uri_split(&us, uri.c_str()) == 0) {
    return (us.field_set & (1 << USR_QUERY)) && us.fields[USR_QUERY].len > 0;
  }
  else {
    return false;
  }
}
} // namespace

bool DefaultBtAnnounce::adjustAnnounceList()
{
  if (isStoppedAnnounceReady()) {
    if (!announceList_.currentTierAcceptsStoppedEvent()) {
      announceList_.moveToStoppedAllowedTier();
    }
    announceList_.setEvent(AnnounceTier::STOPPED);
  }
  else if (isCompletedAnnounceReady()) {
    if (!announceList_.currentTierAcceptsCompletedEvent()) {
      announceList_.moveToCompletedAllowedTier();
    }
    announceList_.setEvent(AnnounceTier::COMPLETED);
  }
  else if (isDefaultAnnounceReady()) {
    // If download completed before "started" event is sent to a tracker,
    // we change the event to something else to prevent us from
    // sending "completed" event.
    if (pieceStorage_->allDownloadFinished() &&
        announceList_.getEvent() == AnnounceTier::STARTED) {
      announceList_.setEvent(AnnounceTier::STARTED_AFTER_COMPLETION);
    }
  }
  else {
    return false;
  }
  return true;
}

namespace {
const char* announceEventToString(AnnounceTier::AnnounceEvent event)
{
  switch (event) {
  case AnnounceTier::STARTED:
  case AnnounceTier::STARTED_AFTER_COMPLETION:
    return "started";
  case AnnounceTier::STOPPED:
    return "stopped";
  case AnnounceTier::COMPLETED:
    return "completed";
  default:
    return "";
  }
}
} // namespace

std::string DefaultBtAnnounce::buildAnnounceUri(
    const std::string& baseUrl, AnnounceTier::AnnounceEvent event)
{
  // numWant 从 50 提高到 200，单次 announce 获取更多 peer
  int numWant = 200;
  if (!btRuntime_->lessThanMinPeers() || btRuntime_->isHalt()) {
    numWant = 0;
  }
  NetStat& stat = downloadContext_->getNetStat();
  int64_t left =
      pieceStorage_->getTotalLength() - pieceStorage_->getCompletedLength();
  // Use last 8 bytes of peer ID as a key
  const size_t keyLen = 8;
  std::string uri = baseUrl;
  uri += uriHasQuery(uri) ? "&" : "?";
  uri +=
      fmt("info_hash=%s&"
          "peer_id=%s&"
          "uploaded=%" PRId64 "&"
          "downloaded=%" PRId64 "&"
          "left=%" PRId64 "&"
          "compact=1&"
          "key=%s&"
          "numwant=%d&"
          "no_peer_id=1",
          util::percentEncode(bittorrent::getInfoHash(downloadContext_),
                              INFO_HASH_LENGTH)
              .c_str(),
          util::percentEncode(bittorrent::getStaticPeerId(), PEER_ID_LENGTH)
              .c_str(),
          stat.getSessionUploadLength(), stat.getSessionDownloadLength(), left,
          util::percentEncode(
              bittorrent::getStaticPeerId() + PEER_ID_LENGTH - keyLen, keyLen)
              .c_str(),
          numWant);
  if (tcpPort_) {
    uri += fmt("&port=%u", tcpPort_);
  }
  const char* eventStr = announceEventToString(event);
  if (eventStr[0]) {
    uri += "&event=";
    uri += eventStr;
  }
  if (!trackerId_.empty()) {
    uri += "&trackerid=";
    uri += util::percentEncode(trackerId_);
  }
  if (option_->getAsBool(PREF_BT_FORCE_ENCRYPTION) ||
      option_->getAsBool(PREF_BT_REQUIRE_CRYPTO)) {
    uri += "&requirecrypto=1";
  }
  else {
    uri += "&supportcrypto=1";
  }
  if (!option_->blank(PREF_BT_EXTERNAL_IP)) {
    uri += "&ip=";
    uri += option_->get(PREF_BT_EXTERNAL_IP);
  }
  return uri;
}

std::string DefaultBtAnnounce::getAnnounceUrl()
{
  if (!adjustAnnounceList()) {
    return A2STR::NIL;
  }
  const std::string& baseUrl = announceList_.getAnnounce();
  if (baseUrl.empty()) {
    return A2STR::NIL;
  }
  return buildAnnounceUri(baseUrl, announceList_.getEvent());
}

std::shared_ptr<UDPTrackerRequest> DefaultBtAnnounce::buildUDPTrackerRequest(
    const std::string& remoteAddr, uint16_t remotePort, uint16_t localPort,
    AnnounceTier::AnnounceEvent event)
{
  NetStat& stat = downloadContext_->getNetStat();
  int64_t left =
      pieceStorage_->getTotalLength() - pieceStorage_->getCompletedLength();
  auto req = std::make_shared<UDPTrackerRequest>();
  req->remoteAddr = remoteAddr;
  req->remotePort = remotePort;
  req->action = UDPT_ACT_ANNOUNCE;
  req->infohash = bittorrent::getTorrentAttrs(downloadContext_)->infoHash;
  const unsigned char* peerId = bittorrent::getStaticPeerId();
  req->peerId.assign(peerId, peerId + PEER_ID_LENGTH);
  req->downloaded = stat.getSessionDownloadLength();
  req->left = left;
  req->uploaded = stat.getSessionUploadLength();
  switch (event) {
  case AnnounceTier::STARTED:
  case AnnounceTier::STARTED_AFTER_COMPLETION:
    req->event = UDPT_EVT_STARTED;
    break;
  case AnnounceTier::STOPPED:
    req->event = UDPT_EVT_STOPPED;
    break;
  case AnnounceTier::COMPLETED:
    req->event = UDPT_EVT_COMPLETED;
    break;
  default:
    req->event = 0;
  }
  if (!option_->blank(PREF_BT_EXTERNAL_IP)) {
    unsigned char dest[16];
    if (net::getBinAddr(dest, option_->get(PREF_BT_EXTERNAL_IP)) == 4) {
      memcpy(&req->ip, dest, 4);
    }
    else {
      req->ip = 0;
    }
  }
  else {
    req->ip = 0;
  }
  req->key = randomizer_->getRandomNumber(INT32_MAX);
  // numWant 从 50 提高到 200，单次 announce 获取更多 peer
  int numWant = 200;
  if (!btRuntime_->lessThanMinPeers() || btRuntime_->isHalt()) {
    numWant = 0;
  }
  req->numWant = numWant;
  req->port = localPort;
  req->extensions = 0;
  return req;
}

std::shared_ptr<UDPTrackerRequest> DefaultBtAnnounce::createUDPTrackerRequest(
    const std::string& remoteAddr, uint16_t remotePort, uint16_t localPort)
{
  if (!adjustAnnounceList()) {
    return nullptr;
  }
  return buildUDPTrackerRequest(remoteAddr, remotePort, localPort,
                                announceList_.getEvent());
}

// === 多 tracker 并发 announce 扩展实现 ===

std::vector<size_t> DefaultBtAnnounce::beginAnnounceCycle()
{
  std::vector<size_t> tiers;
  const size_t n = announceList_.countTier();
  if (n == 0) {
    return tiers;
  }
  // 周期起点：下一周期需等待 minInterval
  prevAnnounceTimer_ = global::wallclock();
  if (isStoppedAnnounceReady()) {
    // 停止事件：向所有接受 stopped 的 tier 各发一次
    for (size_t i = 0; i < n; ++i) {
      if (announceList_.tierAcceptsStoppedEvent(i)) {
        announceList_.setEventOfTier(i, AnnounceTier::STOPPED);
        tiers.push_back(i);
      }
    }
  }
  else if (isCompletedAnnounceReady()) {
    // 完成事件：向所有接受 completed 的 tier 各发一次
    for (size_t i = 0; i < n; ++i) {
      if (announceList_.tierAcceptsCompletedEvent(i)) {
        announceList_.setEventOfTier(i, AnnounceTier::COMPLETED);
        tiers.push_back(i);
      }
    }
  }
  else {
    // 常规周期：对所有 tier 并发 announce
    for (size_t i = 0; i < n; ++i) {
      // 与 adjustAnnounceList 相同的处理：下载已完成但尚未发送过
      // started 的 tier，事件改为 STARTED_AFTER_COMPLETION，避免
      // 误发 completed 事件
      if (pieceStorage_->allDownloadFinished() &&
          announceList_.getEventOfTier(i) == AnnounceTier::STARTED) {
        announceList_.setEventOfTier(i,
                                     AnnounceTier::STARTED_AFTER_COMPLETION);
      }
      tiers.push_back(i);
    }
  }
  return tiers;
}

std::string DefaultBtAnnounce::getAnnounceUrlForTier(size_t tierIndex)
{
  const std::string& baseUrl = announceList_.getAnnounceOfTier(tierIndex);
  if (baseUrl.empty()) {
    return A2STR::NIL;
  }
  return buildAnnounceUri(baseUrl, announceList_.getEventOfTier(tierIndex));
}

std::string DefaultBtAnnounce::getAnnounceBaseUrlOfTier(size_t tierIndex)
{
  return announceList_.getAnnounceOfTier(tierIndex);
}

std::shared_ptr<UDPTrackerRequest>
DefaultBtAnnounce::createUDPTrackerRequestForTier(size_t tierIndex,
                                                  const std::string& remoteAddr,
                                                  uint16_t remotePort,
                                                  uint16_t localPort)
{
  return buildUDPTrackerRequest(remoteAddr, remotePort, localPort,
                                announceList_.getEventOfTier(tierIndex));
}

void DefaultBtAnnounce::announceStartForTier(size_t tierIndex)
{
  ++trackers_;
  currentTrackerUrl_ = announceList_.getAnnounceOfTier(tierIndex);
}

void DefaultBtAnnounce::announceSuccessForTier(size_t tierIndex)
{
  if (trackers_ > 0) {
    --trackers_;
  }
  announceList_.announceSuccessOfTier(tierIndex);
}

bool DefaultBtAnnounce::announceFailureForTier(size_t tierIndex)
{
  if (trackers_ > 0) {
    --trackers_;
  }
  const std::string& url = announceList_.getAnnounceOfTier(tierIndex);
  if (!url.empty()) {
    TrackerStats& stats = trackerStatsMap_[url];
    stats.status = "not-working";
    stats.downloadCount++; // 增加连接次数
  }
  // tier 内轮转到下一个 tracker；返回是否还有可重试的
  return announceList_.announceFailureOfTier(tierIndex);
}

void DefaultBtAnnounce::setCurrentTrackerUrl(const std::string& url)
{
  currentTrackerUrl_ = url;
}

void DefaultBtAnnounce::announceStart() { 
  ++trackers_; 
  currentTrackerUrl_ = announceList_.getAnnounce();
}

void DefaultBtAnnounce::announceSuccess()
{
  trackers_ = 0;
  announceList_.announceSuccess();
}

void DefaultBtAnnounce::announceFailure()
{
  trackers_ = 0;
  if (!currentTrackerUrl_.empty()) {
    TrackerStats& stats = trackerStatsMap_[currentTrackerUrl_];
    stats.status = "not-working";
    stats.downloadCount++;  // 增加连接次数
  }
  announceList_.announceFailure();
}

bool DefaultBtAnnounce::isAllAnnounceFailed()
{
  return announceList_.allTiersFailed();
}

void DefaultBtAnnounce::resetAnnounce()
{
  prevAnnounceTimer_ = global::wallclock();
  announceList_.resetTier();
}

void DefaultBtAnnounce::processAnnounceResponse(
    const unsigned char* trackerResponse, size_t trackerResponseLength)
{
  A2_LOG_DEBUG("Now processing tracker response.");
  auto decodedValue = bencode2::decode(trackerResponse, trackerResponseLength);
  const Dict* dict = downcast<Dict>(decodedValue);
  if (!dict) {
    // 记录失败原因
    if (!currentTrackerUrl_.empty()) {
      TrackerStats& stats = trackerStatsMap_[currentTrackerUrl_];
      stats.failureReason = MSG_NULL_TRACKER_RESPONSE;
    }
    throw DL_ABORT_EX(MSG_NULL_TRACKER_RESPONSE);
  }
  const String* failure =
      downcast<String>(dict->get(BtAnnounce::FAILURE_REASON));
  if (failure) {
    // 记录失败原因
    if (!currentTrackerUrl_.empty()) {
      TrackerStats& stats = trackerStatsMap_[currentTrackerUrl_];
      stats.failureReason = failure->s();
    }
    throw DL_ABORT_EX(fmt(EX_TRACKER_FAILURE, failure->s().c_str()));
  }
  const String* warn = downcast<String>(dict->get(BtAnnounce::WARNING_MESSAGE));
  if (warn) {
    A2_LOG_WARN(fmt(MSG_TRACKER_WARNING_MESSAGE, warn->s().c_str()));
  }
  const String* tid = downcast<String>(dict->get(BtAnnounce::TRACKER_ID));
  if (tid) {
    trackerId_ = tid->s();
    A2_LOG_DEBUG(fmt("Tracker ID:%s", trackerId_.c_str()));
  }
  const Integer* ival = downcast<Integer>(dict->get(BtAnnounce::INTERVAL));
  if (ival && ival->i() > 0) {
    interval_ = std::chrono::seconds(ival->i());
    A2_LOG_DEBUG(fmt("Interval:%ld", static_cast<long int>(interval_.count())));
  }
  const Integer* mival = downcast<Integer>(dict->get(BtAnnounce::MIN_INTERVAL));
  if (mival && mival->i() > 0) {
    minInterval_ = std::chrono::seconds(mival->i());
    A2_LOG_DEBUG(
        fmt("Min interval:%ld", static_cast<long int>(minInterval_.count())));
    minInterval_ = std::min(minInterval_, interval_);
  }
  else {
    // Use interval as a minInterval if minInterval is not supplied.
    minInterval_ = interval_;
  }
  const Integer* comp = downcast<Integer>(dict->get(BtAnnounce::COMPLETE));
  if (comp && comp->i() >= 0) {
    complete_ = comp->i();
    A2_LOG_DEBUG(fmt("Complete:%d", complete_));
  }
  const Integer* incomp = downcast<Integer>(dict->get(BtAnnounce::INCOMPLETE));
  if (incomp && incomp->i() >= 0) {
    incomplete_ = incomp->i();
    A2_LOG_DEBUG(fmt("Incomplete:%d", incomplete_));
  }
  // 统计本次 announce 返回的节点数（独立于是否真正加入 peerStorage）
  int receivedPeerCount = 0;
  auto peerData = dict->get(BtAnnounce::PEERS);
  if (!peerData) {
    A2_LOG_INFO(MSG_NO_PEER_LIST_RECEIVED);
  }
  else {
    std::vector<std::shared_ptr<Peer>> peers;
    bittorrent::extractPeer(peerData, AF_INET, std::back_inserter(peers));
    receivedPeerCount += static_cast<int>(peers.size());
    if (!btRuntime_->isHalt() && btRuntime_->lessThanMinPeers()) {
      peerStorage_->addPeer(peers);
    }
  }
  auto peer6Data = dict->get(BtAnnounce::PEERS6);
  if (!peer6Data) {
    A2_LOG_INFO("No peers6 received.");
  }
  else {
    std::vector<std::shared_ptr<Peer>> peers;
    bittorrent::extractPeer(peer6Data, AF_INET6, std::back_inserter(peers));
    receivedPeerCount += static_cast<int>(peers.size());
    if (!btRuntime_->isHalt() && btRuntime_->lessThanMinPeers()) {
      peerStorage_->addPeer(peers);
    }
  }
  if (!currentTrackerUrl_.empty()) {
    TrackerStats& stats = trackerStatsMap_[currentTrackerUrl_];
    stats.seeders = complete_;
    stats.leechers = incomplete_;
    stats.status = "working";
    stats.failureReason = "";  // 清除失败原因
    stats.downloadCount++;  // 增加连接次数
    stats.peers = receivedPeerCount;  // 记录本次返回的节点数
    // 计算下次连接时间
    stats.nextAnnounceTime = std::chrono::system_clock::now() +
                             std::chrono::duration_cast<std::chrono::system_clock::duration>(minInterval_);
  }
}

void DefaultBtAnnounce::processUDPTrackerResponse(
    const std::shared_ptr<UDPTrackerRequest>& req)
{
  const std::shared_ptr<UDPTrackerReply>& reply = req->reply;
  A2_LOG_DEBUG("Now processing UDP tracker response.");
  if (reply->interval > 0) {
    minInterval_ = std::chrono::seconds(reply->interval);
    A2_LOG_DEBUG(
        fmt("Min interval:%ld", static_cast<long int>(minInterval_.count())));
    interval_ = minInterval_;
  }
  complete_ = reply->seeders;
  A2_LOG_DEBUG(fmt("Complete:%d", reply->seeders));
  incomplete_ = reply->leechers;
  A2_LOG_DEBUG(fmt("Incomplete:%d", reply->leechers));
  if (!currentTrackerUrl_.empty()) {
    TrackerStats& stats = trackerStatsMap_[currentTrackerUrl_];
    stats.seeders = complete_;
    stats.leechers = incomplete_;
    stats.status = "working";
    stats.failureReason = "";  // 清除失败原因
    stats.downloadCount++;  // 增加连接次数
    stats.peers = static_cast<int>(reply->peers.size());  // 记录本次返回的节点数
    // 计算下次连接时间
    stats.nextAnnounceTime = std::chrono::system_clock::now() +
                             std::chrono::duration_cast<std::chrono::system_clock::duration>(minInterval_);
  }
  if (!btRuntime_->isHalt() && btRuntime_->lessThanMinPeers()) {
    for (auto& elem : reply->peers) {
      peerStorage_->addPeer(std::make_shared<Peer>(elem.first, elem.second));
    }
  }
}

bool DefaultBtAnnounce::noMoreAnnounce()
{
  return (trackers_ == 0 && btRuntime_->isHalt() &&
          !announceList_.countStoppedAllowedTier());
}

void DefaultBtAnnounce::shuffleAnnounce() { announceList_.shuffle(); }

void DefaultBtAnnounce::setRandomizer(Randomizer* randomizer)
{
  randomizer_ = randomizer;
}

void DefaultBtAnnounce::setBtRuntime(
    const std::shared_ptr<BtRuntime>& btRuntime)
{
  btRuntime_ = btRuntime;
}

void DefaultBtAnnounce::setPieceStorage(
    const std::shared_ptr<PieceStorage>& pieceStorage)
{
  pieceStorage_ = pieceStorage;
}

void DefaultBtAnnounce::setPeerStorage(
    const std::shared_ptr<PeerStorage>& peerStorage)
{
  peerStorage_ = peerStorage;
}

void DefaultBtAnnounce::overrideMinInterval(std::chrono::seconds interval)
{
  minInterval_ = std::move(interval);
}

} // namespace aria2