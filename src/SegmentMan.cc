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
#include "SegmentMan.h"

#include <cassert>
#include <algorithm>
#include <numeric>

#include "util.h"
#include "message.h"
#include "prefs.h"
#include "PiecedSegment.h"
#include "GrowSegment.h"
#include "LogFactory.h"
#include "Logger.h"
#include "PieceStorage.h"
#include "PeerStat.h"
#include "Option.h"
#include "DownloadContext.h"
#include "Piece.h"
#include "FileEntry.h"
#include "wallclock.h"
#include "fmt.h"
#include "WrDiskCacheEntry.h"
#include "DownloadFailureException.h"

namespace aria2 {

SegmentEntry::SegmentEntry(cuid_t cuid, const std::shared_ptr<Segment>& segment)
    : cuid(cuid), segment(segment)
{
}

SegmentEntry::~SegmentEntry() = default;

SegmentMan::SegmentMan(const std::shared_ptr<DownloadContext>& downloadContext,
                       const std::shared_ptr<PieceStorage>& pieceStorage)
    : downloadContext_(downloadContext),
      pieceStorage_(pieceStorage),
      ignoreBitfield_(downloadContext->getPieceLength(),
                      downloadContext->getTotalLength())
{
  ignoreBitfield_.enableFilter();
}

SegmentMan::~SegmentMan() = default;

bool SegmentMan::downloadFinished() const
{
  if (!pieceStorage_) {
    return false;
  }
  else {
    return pieceStorage_->downloadFinished();
  }
}

void SegmentMan::init()
{
  // TODO Do we have to do something about DownloadContext and
  // PieceStorage here?
}

int64_t SegmentMan::getTotalLength() const
{
  if (!pieceStorage_) {
    return 0;
  }
  else {
    return pieceStorage_->getTotalLength();
  }
}

void SegmentMan::setPieceStorage(
    const std::shared_ptr<PieceStorage>& pieceStorage)
{
  pieceStorage_ = pieceStorage;
}

void SegmentMan::setDownloadContext(
    const std::shared_ptr<DownloadContext>& downloadContext)
{
  downloadContext_ = downloadContext;
}

namespace {
void flushWrDiskCache(WrDiskCache* wrDiskCache,
                      const std::shared_ptr<Piece>& piece)
{
  piece->flushWrCache(wrDiskCache);
  if (piece->getWrDiskCacheEntry()->getError() !=
      WrDiskCacheEntry::CACHE_ERR_SUCCESS) {
    piece->clearAllBlock(wrDiskCache);
    throw DOWNLOAD_FAILURE_EXCEPTION2(
        fmt("Write disk cache flush failure index=%lu",
            static_cast<unsigned long>(piece->getIndex())),
        piece->getWrDiskCacheEntry()->getErrorCode());
  }
}
} // namespace

std::shared_ptr<Segment>
SegmentMan::checkoutSegment(cuid_t cuid, const std::shared_ptr<Piece>& piece)
{
  if (!piece) {
    return nullptr;
  }
  A2_LOG_DEBUG(fmt("Attach segment#%lu to CUID#%" PRId64 ".",
                   static_cast<unsigned long>(piece->getIndex()), cuid));

  if (piece->getWrDiskCacheEntry()) {
    // Flush cached data here, because the cached data may be overlapped
    // if BT peers are involved.
    A2_LOG_DEBUG(fmt(
        "Flushing cached data, size=%lu",
        static_cast<unsigned long>(piece->getWrDiskCacheEntry()->getSize())));
    flushWrDiskCache(pieceStorage_->getWrDiskCache(), piece);
  }

  piece->setUsedBySegment(true);
  std::shared_ptr<Segment> segment;
  if (piece->getLength() == 0) {
    segment = std::make_shared<GrowSegment>(piece);
  }
  else {
    segment = std::make_shared<PiecedSegment>(
        downloadContext_->getPieceLength(), piece);
  }
  auto entry = std::make_shared<SegmentEntry>(cuid, segment);
  usedSegmentEntries_.push_back(entry);
  A2_LOG_DEBUG(fmt("index=%lu, length=%" PRId64 ", segmentLength=%" PRId64 ","
                   " writtenLength=%" PRId64,
                   static_cast<unsigned long>(segment->getIndex()),
                   segment->getLength(), segment->getSegmentLength(),
                   segment->getWrittenLength()));

  if (piece->getLength() > 0) {
    auto positr = segmentWrittenLengthMemo_.find(segment->getIndex());
    if (positr != segmentWrittenLengthMemo_.end()) {
      const auto writtenLength = (*positr).second;
      A2_LOG_DEBUG(fmt("writtenLength(in memo)=%" PRId64
                       ", writtenLength=%" PRId64,
                       writtenLength, segment->getWrittenLength()));
      //  If the difference between cached writtenLength and segment's
      //  writtenLength is less than one block, we assume that these
      //  missing bytes are already downloaded.
      if (segment->getWrittenLength() < writtenLength &&
          writtenLength - segment->getWrittenLength() <
              piece->getBlockLength()) {
        segment->updateWrittenLength(writtenLength -
                                     segment->getWrittenLength());
      }
    }
  }
  return segment;
}

void SegmentMan::getInFlightSegment(
    std::vector<std::shared_ptr<Segment>>& segments, cuid_t cuid)
{
  for (SegmentEntries::const_iterator itr = usedSegmentEntries_.begin(),
                                      eoi = usedSegmentEntries_.end();
       itr != eoi; ++itr) {
    const std::shared_ptr<SegmentEntry>& segmentEntry = *itr;
    if (segmentEntry->cuid == cuid) {
      segments.push_back(segmentEntry->segment);
    }
  }
}

std::shared_ptr<Segment> SegmentMan::getSegment(cuid_t cuid,
                                                size_t minSplitSize)
{
  // Use dynamically calculated segment size
  size_t dynamicSize = static_cast<size_t>(getDynamicSegmentSize());
  
  // Use the larger of specified minSplitSize or dynamic size
  size_t actualSize = std::max(minSplitSize, dynamicSize);
  
  std::shared_ptr<Piece> piece = pieceStorage_->getMissingPiece(
      actualSize, ignoreBitfield_.getFilterBitfield(),
      ignoreBitfield_.getBitfieldLength(), cuid);
  return checkoutSegment(cuid, piece);
}

void SegmentMan::getSegment(std::vector<std::shared_ptr<Segment>>& segments,
                            cuid_t cuid, size_t minSplitSize,
                            const std::shared_ptr<FileEntry>& fileEntry,
                            size_t maxSegments)
{
  BitfieldMan filter(ignoreBitfield_);
  filter.enableFilter();
  filter.addNotFilter(fileEntry->getOffset(), fileEntry->getLength());
  std::vector<std::shared_ptr<Segment>> pending;
  while (segments.size() < maxSegments) {
    std::shared_ptr<Segment> segment = checkoutSegment(
        cuid,
        pieceStorage_->getMissingPiece(minSplitSize, filter.getFilterBitfield(),
                                       filter.getBitfieldLength(), cuid));
    if (!segment) {
      break;
    }
    if (segment->getPositionToWrite() < fileEntry->getOffset() ||
        fileEntry->getLastOffset() <= segment->getPositionToWrite()) {
      pending.push_back(segment);
    }
    else {
      segments.push_back(segment);
    }
  }
  for (std::vector<std::shared_ptr<Segment>>::const_iterator
           i = pending.begin(),
           eoi = pending.end();
       i != eoi; ++i) {
    cancelSegment(cuid, *i);
  }
}

std::shared_ptr<Segment> SegmentMan::getSegmentWithIndex(cuid_t cuid,
                                                         size_t index)
{
  if (index > 0 && downloadContext_->getNumPieces() <= index) {
    return nullptr;
  }
  return checkoutSegment(cuid, pieceStorage_->getMissingPiece(index, cuid));
}

std::shared_ptr<Segment> SegmentMan::getCleanSegmentIfOwnerIsIdle(cuid_t cuid,
                                                                  size_t index)
{
  if (index > 0 && downloadContext_->getNumPieces() <= index) {
    return nullptr;
  }
  for (SegmentEntries::const_iterator itr = usedSegmentEntries_.begin(),
                                      eoi = usedSegmentEntries_.end();
       itr != eoi; ++itr) {
    const std::shared_ptr<SegmentEntry>& segmentEntry = *itr;
    if (segmentEntry->segment->getIndex() == index) {
      if (segmentEntry->segment->getWrittenLength() > 0) {
        return nullptr;
      }
      if (segmentEntry->cuid == cuid) {
        return segmentEntry->segment;
      }
      cuid_t owner = segmentEntry->cuid;
      std::shared_ptr<PeerStat> ps = getPeerStat(owner);
      if (!ps || ps->getStatus() == NetStat::IDLE) {
        cancelSegment(owner);
        return getSegmentWithIndex(cuid, index);
      }
      else {
        return nullptr;
      }
    }
  }
  return nullptr;
}

void SegmentMan::cancelSegmentInternal(cuid_t cuid,
                                       const std::shared_ptr<Segment>& segment)
{
  A2_LOG_DEBUG(fmt("Canceling segment#%lu",
                   static_cast<unsigned long>(segment->getIndex())));
  const std::shared_ptr<Piece>& piece = segment->getPiece();
  // TODO In PieceStorage::cancelPiece(), WrDiskCacheEntry may be
  // released. Flush first.
  if (piece->getWrDiskCacheEntry()) {
    // Flush cached data here, because the cached data may be overlapped
    // if BT peers are involved.
    A2_LOG_DEBUG(fmt(
        "Flushing cached data, size=%lu",
        static_cast<unsigned long>(piece->getWrDiskCacheEntry()->getSize())));
    flushWrDiskCache(pieceStorage_->getWrDiskCache(), piece);
    // TODO Exception may cause some segments (pieces) are not
    // canceled.
  }
  piece->setUsedBySegment(false);
  pieceStorage_->cancelPiece(piece, cuid);
  segmentWrittenLengthMemo_[segment->getIndex()] = segment->getWrittenLength();
  A2_LOG_DEBUG(fmt("Memorized segment index=%lu, writtenLength=%" PRId64,
                   static_cast<unsigned long>(segment->getIndex()),
                   segment->getWrittenLength()));
}

void SegmentMan::cancelSegment(cuid_t cuid)
{
  for (auto itr = usedSegmentEntries_.begin(), eoi = usedSegmentEntries_.end();
       itr != eoi;) {
    if ((*itr)->cuid == cuid) {
      cancelSegmentInternal(cuid, (*itr)->segment);
      itr = usedSegmentEntries_.erase(itr);
      eoi = usedSegmentEntries_.end();
    }
    else {
      ++itr;
    }
  }
}

void SegmentMan::cancelSegment(cuid_t cuid,
                               const std::shared_ptr<Segment>& segment)
{
  for (auto itr = usedSegmentEntries_.begin(), eoi = usedSegmentEntries_.end();
       itr != eoi;) {
    if ((*itr)->cuid == cuid && *(*itr)->segment == *segment) {
      cancelSegmentInternal(cuid, (*itr)->segment);
      itr = usedSegmentEntries_.erase(itr);
      break;
    }
    else {
      ++itr;
    }
  }
}

void SegmentMan::cancelAllSegments()
{
  for (auto& e : usedSegmentEntries_) {
    cancelSegmentInternal(e->cuid, e->segment);
  }
  usedSegmentEntries_.clear();
}

void SegmentMan::eraseSegmentWrittenLengthMemo()
{
  segmentWrittenLengthMemo_.clear();
}

namespace {
class FindSegmentEntry {
private:
  std::shared_ptr<Segment> segment_;

public:
  FindSegmentEntry(std::shared_ptr<Segment> segment)
      : segment_(std::move(segment))
  {
  }

  bool operator()(const std::shared_ptr<SegmentEntry>& segmentEntry) const
  {
    return segmentEntry->segment->getIndex() == segment_->getIndex();
  }
};
} // namespace

bool SegmentMan::completeSegment(cuid_t cuid,
                                 const std::shared_ptr<Segment>& segment)
{
  pieceStorage_->completePiece(segment->getPiece());
  pieceStorage_->advertisePiece(cuid, segment->getPiece()->getIndex(),
                                global::wallclock());
  auto itr = std::find_if(usedSegmentEntries_.begin(),
                          usedSegmentEntries_.end(), FindSegmentEntry(segment));
  if (itr == usedSegmentEntries_.end()) {
    return false;
  }
  else {
    usedSegmentEntries_.erase(itr);
    return true;
  }
}

bool SegmentMan::hasSegment(size_t index) const
{
  return pieceStorage_->hasPiece(index);
}

int64_t SegmentMan::getDownloadLength() const
{
  if (!pieceStorage_) {
    return 0;
  }
  else {
    return pieceStorage_->getCompletedLength();
  }
}

void SegmentMan::registerPeerStat(const std::shared_ptr<PeerStat>& peerStat)
{
  peerStats_.push_back(peerStat);
}

std::shared_ptr<PeerStat> SegmentMan::getPeerStat(cuid_t cuid) const
{
  for (auto& e : peerStats_) {
    if (e->getCuid() == cuid) {
      return e;
    }
  }
  return nullptr;
}

namespace {
class PeerStatHostProtoEqual {
private:
  const std::shared_ptr<PeerStat>& peerStat_;

public:
  PeerStatHostProtoEqual(const std::shared_ptr<PeerStat>& peerStat)
      : peerStat_(peerStat)
  {
  }

  bool operator()(const std::shared_ptr<PeerStat>& p) const
  {
    return peerStat_->getHostname() == p->getHostname() &&
           peerStat_->getProtocol() == p->getProtocol();
  }
};
} // namespace

void SegmentMan::updateFastestPeerStat(
    const std::shared_ptr<PeerStat>& peerStat)
{
  auto i = std::find_if(fastestPeerStats_.begin(), fastestPeerStats_.end(),
                        PeerStatHostProtoEqual(peerStat));
  if (i == fastestPeerStats_.end()) {
    fastestPeerStats_.push_back(peerStat);
  }
  else if ((*i)->getAvgDownloadSpeed() < peerStat->getAvgDownloadSpeed()) {
    // *i's SessionDownloadLength must be added to peerStat
    peerStat->addSessionDownloadLength((*i)->getSessionDownloadLength());
    *i = peerStat;
  }
  else {
    // peerStat's SessionDownloadLength must be added to *i
    (*i)->addSessionDownloadLength(peerStat->getSessionDownloadLength());
  }
}

size_t SegmentMan::countFreePieceFrom(size_t index) const
{
  size_t numPieces = downloadContext_->getNumPieces();
  for (size_t i = index; i < numPieces; ++i) {
    if (pieceStorage_->hasPiece(i) || pieceStorage_->isPieceUsed(i)) {
      return i - index;
    }
  }
  return downloadContext_->getNumPieces() - index;
}

void SegmentMan::ignoreSegmentFor(const std::shared_ptr<FileEntry>& fileEntry)
{
  A2_LOG_DEBUG(fmt("ignoring segment for path=%s, offset=%" PRId64
                   ", length=%" PRId64 "",
                   fileEntry->getPath().c_str(), fileEntry->getOffset(),
                   fileEntry->getLength()));
  ignoreBitfield_.addFilter(fileEntry->getOffset(), fileEntry->getLength());
}

void SegmentMan::recognizeSegmentFor(
    const std::shared_ptr<FileEntry>& fileEntry)
{
  ignoreBitfield_.removeFilter(fileEntry->getOffset(), fileEntry->getLength());
}

bool SegmentMan::allSegmentsIgnored() const
{
  return ignoreBitfield_.isAllFilterBitSet();
}

// Dynamic segmentation implementation
void SegmentMan::updateConnectionStats(cuid_t cuid, int64_t downloadedBytes)
{
  auto now = std::chrono::steady_clock::now();
  auto& stats = connectionStats_[cuid];
  
  if (stats.cuid == 0) {
    // First time initialization
    stats.cuid = cuid;
    stats.startTime = now;
    stats.lastUpdateTime = now;
    stats.totalDownloaded = 0;
    stats.currentSpeed = 0;
    stats.avgSpeed = 0;
    stats.remainingBytes = 0;
    stats.isIdle = false;
  }
  
  // Calculate instantaneous speed
  auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
      now - stats.lastUpdateTime);
  
  if (elapsed.count() > 0) {
    int64_t newBytes = downloadedBytes - stats.totalDownloaded;
    double instantSpeed = static_cast<double>(newBytes) * 1000.0 / elapsed.count();
    
    // Use EMA (Exponential Moving Average) to smooth the speed
    // This prevents noisy instantaneous speed from causing unnecessary
    // segment reallocations, which would interrupt downloads and cause
    // speed fluctuations.
    // alpha = 0.3 gives weight to recent data while maintaining stability
    constexpr double alpha = 0.3;
    if (stats.currentSpeed == 0) {
      stats.currentSpeed = instantSpeed;
    } else {
      stats.currentSpeed = alpha * instantSpeed + (1.0 - alpha) * stats.currentSpeed;
    }
  }
  
  stats.totalDownloaded = downloadedBytes;
  
  // Calculate average speed
  auto totalElapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
      now - stats.startTime);
  if (totalElapsed.count() > 0) {
    stats.avgSpeed = static_cast<double>(stats.totalDownloaded) * 1000.0 / 
                     totalElapsed.count();
  }
  
  // Update remaining bytes
  stats.remainingBytes = 0;
  for (const auto& entry : usedSegmentEntries_) {
    if (entry->cuid == cuid) {
      const auto& seg = entry->segment;
      stats.remainingBytes += seg->getLength() - seg->getWrittenLength();
    }
  }
  
  stats.isIdle = (stats.remainingBytes == 0);
  stats.lastUpdateTime = now;
}

int64_t SegmentMan::getDynamicSegmentSize() const
{
  int64_t totalRemaining = getTotalLength() - getDownloadLength();
  if (totalRemaining <= 0) {
    return DYNAMIC_MIN_SPLIT_SIZE;
  }
  
  double progress = getDownloadProgress();
  int activeConnections = 0;
  
  // Count active connections
  for (const auto& pair : connectionStats_) {
    if (!pair.second.isIdle) {
      activeConnections++;
    }
  }
  
  if (activeConnections == 0) {
    activeConnections = 1;
  }
  
  int64_t segmentSize;
  
  // 末尾加速模式：进度 > 90%
  if (progress > ENDGAME_PROGRESS_THRESHOLD) {
    // 使用更小的分段，提高并发度
    // 每个连接分配更多更小的段，确保所有连接都能参与
    segmentSize = totalRemaining / (activeConnections * 8);
    
    // 使用更小的最小分段大小
    if (segmentSize < ENDGAME_MIN_SPLIT_SIZE) {
      segmentSize = ENDGAME_MIN_SPLIT_SIZE;
    } else if (segmentSize > DYNAMIC_MIN_SPLIT_SIZE) {
      segmentSize = DYNAMIC_MIN_SPLIT_SIZE;
    }
    
    A2_LOG_DEBUG(fmt("ENDGAME MODE: progress=%.1f%%, segmentSize=%" PRId64 ", activeConn=%d",
                     progress * 100, segmentSize, activeConnections));
  }
  // 接近完成模式：进度 > 85%
  else if (progress > PREEMPTION_PROGRESS_THRESHOLD) {
    // 使用较小的分段
    segmentSize = std::max(totalRemaining / (activeConnections * 4), 
                          DYNAMIC_MIN_SPLIT_SIZE);
  } 
  // 正常下载模式
  else {
    // 使用标准分段
    segmentSize = totalRemaining / (activeConnections * 4);
    // Manual clamp for C++11/14 compatibility
    if (segmentSize < DYNAMIC_MIN_SPLIT_SIZE) {
      segmentSize = DYNAMIC_MIN_SPLIT_SIZE;
    } else if (segmentSize > DYNAMIC_MAX_SPLIT_SIZE) {
      segmentSize = DYNAMIC_MAX_SPLIT_SIZE;
    }
  }
  
  return segmentSize;
}

void SegmentMan::scheduleSegments()
{
  auto now = std::chrono::steady_clock::now();
  
  // 末尾加速模式：更频繁的调度（每0.5秒）
  bool endgameMode = isEndgameMode();
  int64_t scheduleIntervalMs = endgameMode ? ENDGAME_SCHEDULE_INTERVAL_MS : (SCHEDULE_INTERVAL_SEC * 1000);
  
  // Check schedule interval
  if (std::chrono::duration_cast<std::chrono::milliseconds>(
        now - lastScheduleTime_).count() < scheduleIntervalMs) {
    return;
  }
  
  lastScheduleTime_ = now;
  
  if (endgameMode) {
    A2_LOG_DEBUG("ENDGAME MODE: Aggressive scheduling active");
    // 末尾加速：强制重新分配所有慢速连接
    forceReallocateAllSlowSegments();
  }
  
  // Find slow connections that need reallocation
  std::vector<cuid_t> slowConnections;
  for (const auto& pair : connectionStats_) {
    if (shouldReallocateSegment(pair.first)) {
      slowConnections.push_back(pair.first);
    }
  }
  
  // Perform reallocation
  int reallocatedCount = 0;
  for (cuid_t slowCuid : slowConnections) {
    if (splitAndReallocateSegment(slowCuid)) {
      reallocatedCount++;
      A2_LOG_INFO(fmt("Reallocated segment from slow connection CUID#%" PRId64, 
                      slowCuid));
    }
  }
  
  if (endgameMode && reallocatedCount > 0) {
    A2_LOG_INFO(fmt("ENDGAME MODE: Reallocated %d segments", reallocatedCount));
  }
}

bool SegmentMan::shouldReallocateSegment(cuid_t cuid) const
{
  auto it = connectionStats_.find(cuid);
  if (it == connectionStats_.end() || it->second.isIdle) {
    return false;
  }
  
  const auto& stats = it->second;
  
  // Avoid reallocating segments for connections that just started.
  // A connection needs time to ramp up to full speed; reallocating
  // too early causes unnecessary churn and speed drops.
  auto connectionAge = std::chrono::duration_cast<std::chrono::seconds>(
      std::chrono::steady_clock::now() - stats.startTime);
  if (connectionAge.count() < 3) {
    return false;
  }
  
  // 末尾加速模式：更激进的重新分配策略
  bool endgameMode = isEndgameMode();
  
  // 在末尾加速模式下，即使是较小的数据也值得重新分配
  int64_t minRemainingThreshold = endgameMode ? ENDGAME_MIN_SPLIT_SIZE : (DYNAMIC_MIN_SPLIT_SIZE * 2);
  
  if (stats.remainingBytes < minRemainingThreshold) {
    return false;
  }
  
  double avgSpeed = calculateAverageSpeed();
  if (avgSpeed <= 0) {
    return false;
  }
  
  double progress = getDownloadProgress();
  
  // Use relative slow threshold based on average speed.
  // With EMA-smoothed currentSpeed, we can use the same threshold
  // for both endgame and normal modes to avoid over-aggressive
  // reallocation in endgame mode.
  double slowThreshold = SLOW_CONNECTION_THRESHOLD;
  
  // Condition 1: Speed too slow
  if (stats.currentSpeed < avgSpeed * slowThreshold) {
    if (endgameMode) {
      A2_LOG_DEBUG(fmt("ENDGAME: CUID#%" PRId64 " is slow: %.1f KB/s < %.1f KB/s * %.2f",
                       cuid, stats.currentSpeed / 1024.0, avgSpeed / 1024.0, slowThreshold));
    }
    return true;
  }
  
  // Condition 2: Near completion and very slow
  // Use relative threshold (15% of average) with a floor of 50KB/s
  // to avoid flagging all connections when overall speed is low
  if (progress > PREEMPTION_PROGRESS_THRESHOLD) {
    double relThreshold = std::max(avgSpeed * 0.15, 50.0 * 1024.0);
    if (stats.currentSpeed < relThreshold) {
      return true;
    }
  }
  
  // Condition 3: Remaining bytes far exceed average
  int64_t totalRemaining = 0;
  int activeCount = 0;
  for (const auto& pair : connectionStats_) {
    if (!pair.second.isIdle) {
      totalRemaining += pair.second.remainingBytes;
      activeCount++;
    }
  }
  
  if (activeCount > 1) {
    int64_t avgRemaining = totalRemaining / activeCount;
    // 末尾加速模式：更激进的负载均衡（2倍而不是3倍）
    int multiplier = endgameMode ? 2 : 3;
    if (stats.remainingBytes > avgRemaining * multiplier) {
      return true;
    }
  }
  
  return false;
}

bool SegmentMan::splitAndReallocateSegment(cuid_t slowCuid)
{
  // Find slow connection's segment
  std::shared_ptr<SegmentEntry> slowEntry;
  for (const auto& entry : usedSegmentEntries_) {
    if (entry->cuid == slowCuid) {
      slowEntry = entry;
      break;
    }
  }
  
  if (!slowEntry) {
    return false;
  }
  
  const auto& slowSegment = slowEntry->segment;
  int64_t remaining = slowSegment->getLength() - slowSegment->getWrittenLength();

  // Calculate split size (half of remaining)
  int64_t splitSize = remaining / 2;
  // In endgame mode, allow smaller splits to keep connections busy
  int64_t minSplit = isEndgameMode() ? ENDGAME_MIN_SPLIT_SIZE : DYNAMIC_MIN_SPLIT_SIZE;
  if (splitSize < minSplit) {
    return false;
  }
  
  // Find best connection (idle or fastest)
  cuid_t bestCuid = findBestConnection(slowCuid);
  if (bestCuid == 0) {
    return false;
  }
  
  // Try to get an unassigned piece for the fast connection
  auto piece = pieceStorage_->getMissingPiece(splitSize, 
                                              ignoreBitfield_.getFilterBitfield(),
                                              ignoreBitfield_.getBitfieldLength(), 
                                              bestCuid);
  if (!piece) {
    // No unassigned pieces available. Cancel the slow connection's segment
    // to free up its remaining bytes for the fast connection.
    // This is safe in aria2's single-threaded event loop: the slow
    // connection's DownloadCommand is not executing at this moment
    // (it's waiting for socket data), so there's no race condition.
    // When the slow connection's command next executes, it will detect
    // the cancellation via getInFlightSegment() returning empty, then
    // get a new smaller segment or become idle.
    A2_LOG_INFO(fmt("Canceling slow CUID#%" PRId64 " segment (%" PRId64
                    " bytes remaining) to reallocate to fast CUID#%" PRId64,
                    slowCuid, remaining, bestCuid));
    cancelSegment(slowCuid, slowSegment);
    
    // Now try again to get a piece from the freed bytes
    piece = pieceStorage_->getMissingPiece(splitSize,
                                           ignoreBitfield_.getFilterBitfield(),
                                           ignoreBitfield_.getBitfieldLength(),
                                           bestCuid);
    if (!piece) {
      return false;
    }
    
    // Give the slow connection a smaller segment too so it still has work
    auto slowPiece = pieceStorage_->getMissingPiece(minSplit,
                                                     ignoreBitfield_.getFilterBitfield(),
                                                     ignoreBitfield_.getBitfieldLength(),
                                                     slowCuid);
    if (slowPiece) {
      checkoutSegment(slowCuid, slowPiece);
    }
  }
  
  auto newSegment = checkoutSegment(bestCuid, piece);
  if (!newSegment) {
    return false;
  }
  
  auto slowIt = connectionStats_.find(slowCuid);
  if (slowIt != connectionStats_.end()) {
    A2_LOG_INFO(fmt("Split segment: slow CUID#%" PRId64 " (%.1f KB/s, %" PRId64 " bytes) "
                    "-> fast CUID#%" PRId64 " (%" PRId64 " bytes)",
                    slowCuid, 
                    slowIt->second.currentSpeed / 1024.0,
                    remaining,
                    bestCuid,
                    splitSize));
  }
  
  return true;
}

cuid_t SegmentMan::findBestConnection(cuid_t excludeCuid) const
{
  cuid_t bestCuid = 0;
  double bestSpeed = -1;
  
  for (const auto& pair : connectionStats_) {
    if (pair.first == excludeCuid) {
      continue;
    }
    
    // Prefer idle connections
    if (pair.second.isIdle) {
      return pair.first;
    }
    
    // Otherwise choose fastest connection
    if (pair.second.currentSpeed > bestSpeed) {
      bestSpeed = pair.second.currentSpeed;
      bestCuid = pair.first;
    }
  }
  
  return bestCuid;
}

double SegmentMan::calculateAverageSpeed() const
{
  if (connectionStats_.empty()) {
    return 0;
  }
  
  double totalSpeed = 0;
  int activeCount = 0;
  
  for (const auto& pair : connectionStats_) {
    if (!pair.second.isIdle) {
      totalSpeed += pair.second.currentSpeed;
      activeCount++;
    }
  }
  
  return activeCount > 0 ? totalSpeed / activeCount : 0;
}

double SegmentMan::getDownloadProgress() const
{
  int64_t total = getTotalLength();
  if (total <= 0) {
    return 0;
  }
  
  int64_t downloaded = getDownloadLength();
  return static_cast<double>(downloaded) / total;
}

bool SegmentMan::isEndgameMode() const
{
  double progress = getDownloadProgress();
  return progress > ENDGAME_PROGRESS_THRESHOLD;
}

void SegmentMan::forceReallocateAllSlowSegments()
{
  // 末尾加速模式：更激进的重新分配策略
  // 找出所有慢速连接并强制重新分配
  
  double avgSpeed = calculateAverageSpeed();
  if (avgSpeed <= 0) {
    return;
  }
  
  // 在末尾加速模式下，使用更宽松的慢速判断标准（45%而不是30%）
  double slowThreshold = SLOW_CONNECTION_THRESHOLD * 1.5;  // 45%
  
  std::vector<cuid_t> slowConnections;
  
  for (const auto& pair : connectionStats_) {
    const auto& stats = pair.second;
    
    // 跳过空闲连接
    if (stats.isIdle) {
      continue;
    }
    
    // 剩余数据太少，不值得重新分配
    if (stats.remainingBytes < ENDGAME_MIN_SPLIT_SIZE) {
      continue;
    }
    
    // 判断是否为慢速连接
    bool isSlow = false;
    
    // 条件1：速度低于平均速度的45%
    if (stats.currentSpeed < avgSpeed * slowThreshold) {
      isSlow = true;
      A2_LOG_DEBUG(fmt("ENDGAME: CUID#%" PRId64 " is slow (speed): %.1f KB/s < %.1f KB/s * %.2f",
                       pair.first, stats.currentSpeed / 1024.0, avgSpeed / 1024.0, slowThreshold));
    }
    
    // 条件2：速度低于200KB/s（末尾加速阈值）
    if (stats.currentSpeed < 200 * 1024) {
      isSlow = true;
      A2_LOG_DEBUG(fmt("ENDGAME: CUID#%" PRId64 " is slow (threshold): %.1f KB/s < 200 KB/s",
                       pair.first, stats.currentSpeed / 1024.0));
    }
    
    // 条件3：剩余数据量远超平均值（2倍而不是3倍）
    int64_t totalRemaining = 0;
    int activeCount = 0;
    for (const auto& p : connectionStats_) {
      if (!p.second.isIdle) {
        totalRemaining += p.second.remainingBytes;
        activeCount++;
      }
    }
    
    if (activeCount > 1) {
      int64_t avgRemaining = totalRemaining / activeCount;
      if (stats.remainingBytes > avgRemaining * 2) {
        isSlow = true;
        A2_LOG_DEBUG(fmt("ENDGAME: CUID#%" PRId64 " has too much remaining: %" PRId64 " > %" PRId64 " * 2",
                         pair.first, stats.remainingBytes, avgRemaining));
      }
    }
    
    if (isSlow) {
      slowConnections.push_back(pair.first);
    }
  }
  
  // 对所有慢速连接执行重新分配
  int reallocatedCount = 0;
  for (cuid_t slowCuid : slowConnections) {
    if (splitAndReallocateSegment(slowCuid)) {
      reallocatedCount++;
      A2_LOG_INFO(fmt("ENDGAME: Force reallocated segment from CUID#%" PRId64, slowCuid));
    }
  }
  
  if (reallocatedCount > 0) {
    A2_LOG_INFO(fmt("ENDGAME: Force reallocated %d segments in total", reallocatedCount));
  }
}

} // namespace aria2
