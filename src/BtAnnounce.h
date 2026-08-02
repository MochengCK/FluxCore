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
#ifndef D_BT_ANNOUNCE_H
#define D_BT_ANNOUNCE_H

#include "common.h"

#include <string>
#include <memory>
#include <vector>

#include "a2time.h"
#include "a2functional.h"
#include "A2STR.h"

namespace aria2 {

struct UDPTrackerRequest;

class BtAnnounce {
public:
  virtual ~BtAnnounce() = default;

  /**
   * Returns true if announce is required.
   * Otherwise returns false.
   *
   * There are 4 announce timings:
   * 1) started: when a download just started.
   * 2) stopped: when the client quits.
   * 3) completed: when a download just completed.
   * 4) When a certain amount of time, aka announce interval, specified by
   *    a tracker, is elapsed.
   */
  virtual bool isAnnounceReady() = 0;

  /**
   * Returns announe URL with all necessary parameters included.
   */
  virtual std::string getAnnounceUrl() = 0;

  virtual std::shared_ptr<UDPTrackerRequest>
  createUDPTrackerRequest(const std::string& remoteAddr, uint16_t remotePort,
                          uint16_t localPort) = 0;

  /**
   * Tells that the announce process has just started.
   */
  virtual void announceStart() = 0;

  /**
   * Tells that the announce succeeded.
   */
  virtual void announceSuccess() = 0;

  /**
   * Tells that the announce failed.
   */
  virtual void announceFailure() = 0;

  /**
   * Returns true if all announce attempt failed.
   */
  virtual bool isAllAnnounceFailed() = 0;

  /**
   * Resets announce status.
   */
  virtual void resetAnnounce() = 0;

  /**
   * Processes the repsponse from the tracker.
   */
  virtual void processAnnounceResponse(const unsigned char* trackerResponse,
                                       size_t trackerResponseLength) = 0;

  virtual void
  processUDPTrackerResponse(const std::shared_ptr<UDPTrackerRequest>& req) = 0;

  /**
   * Returns true if no more announce is needed.
   */
  virtual bool noMoreAnnounce() = 0;

  /**
   * Shuffles the URLs in each announce tier.
   */
  virtual void shuffleAnnounce() = 0;

  virtual void overrideMinInterval(std::chrono::seconds interval) = 0;

  virtual void setTcpPort(uint16_t port) = 0;

  // === 多 tracker 并发 announce 扩展 ===
  // 以下方法支持对一个 announce 周期内的所有 tier 并发 announce。
  // 默认实现委托给旧的单 tracker 方法，保持既有 Mock / 调用方行为不变。

  // 开始一个 announce 周期，返回本周期待 announce 的 tier 索引列表。
  // 默认返回 {0}，即旧的单 tracker 行为。
  virtual std::vector<size_t> beginAnnounceCycle() { return {0}; }

  // 返回指定 tier 当前 tracker 的完整 announce URI（含参数）。
  virtual std::string getAnnounceUrlForTier(size_t tierIndex)
  {
    return getAnnounceUrl();
  }

  // 返回指定 tier 当前 tracker 的基础 URL（不含参数），用于统计归属。
  virtual std::string getAnnounceBaseUrlOfTier(size_t tierIndex)
  {
    return A2STR::NIL;
  }

  virtual std::shared_ptr<UDPTrackerRequest>
  createUDPTrackerRequestForTier(size_t tierIndex,
                                 const std::string& remoteAddr,
                                 uint16_t remotePort, uint16_t localPort)
  {
    return createUDPTrackerRequest(remoteAddr, remotePort, localPort);
  }

  // 指定 tier 的 announce 已发出。
  virtual void announceStartForTier(size_t tierIndex) { announceStart(); }

  // 指定 tier 的 announce 成功。
  virtual void announceSuccessForTier(size_t tierIndex) { announceSuccess(); }

  // 指定 tier 的 announce 失败。返回 true 表示该 tier 内还有
  // 其他 tracker 可立即重试。
  virtual bool announceFailureForTier(size_t tierIndex)
  {
    announceFailure();
    return false;
  }

  // 设置后续 processAnnounceResponse / processUDPTrackerResponse
  // 统计归属的 tracker URL（单线程事件循环内同步使用）。
  virtual void setCurrentTrackerUrl(const std::string& url) {}

  static const std::string FAILURE_REASON;

  static const std::string WARNING_MESSAGE;

  static const std::string TRACKER_ID;

  static const std::string INTERVAL;

  static const std::string MIN_INTERVAL;

  static const std::string COMPLETE;

  static const std::string INCOMPLETE;

  static const std::string PEERS;

  static const std::string PEERS6;

  constexpr static auto DEFAULT_ANNOUNCE_INTERVAL = 2_min;
};

} // namespace aria2

#endif // D_BT_ANNOUNCE_H
