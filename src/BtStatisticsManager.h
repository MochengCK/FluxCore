/* <!-- copyright */
/*
 * aria2 - The high speed download utility
 *
 * Copyright (C) 2025 LinkCore Development Team
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
#ifndef D_BT_STATISTICS_MANAGER_H
#define D_BT_STATISTICS_MANAGER_H

#include "common.h"

#include <string>
#include <mutex>
#include <cstdint>

namespace aria2 {

/**
 * BtStatisticsManager manages persistent BitTorrent statistics including
 * cumulative download/upload bytes, seed time, and maximum peer connections.
 * 
 * This class provides thread-safe access to statistics and handles persistence
 * to disk with atomic writes and CRC32 checksum verification.
 */
class BtStatisticsManager {
public:
  /**
   * Constructor
   * @param storageFilePath Path to the statistics storage file
   */
  BtStatisticsManager(const std::string& storageFilePath);

  ~BtStatisticsManager();

  // Lifecycle methods
  
  /**
   * Load statistics from disk on startup.
   * If file doesn't exist or is corrupted, initializes to zero.
   */
  void load();

  /**
   * Save statistics to disk atomically.
   * Uses temporary file and rename to prevent corruption.
   */
  void save();

  // Statistics update methods (thread-safe)
  
  /**
   * Add bytes to cumulative download count
   * @param bytes Number of bytes downloaded
   */
  void addDownloadBytes(uint64_t bytes);

  /**
   * Add bytes to cumulative upload count
   * @param bytes Number of bytes uploaded
   */
  void addUploadBytes(uint64_t bytes);

  /**
   * Add seconds to cumulative seed time
   * @param seconds Number of seconds spent seeding
   */
  void addSeedTime(uint32_t seconds);

  /**
   * Update maximum peer count if current count is higher
   * @param currentPeers Current number of connected peers
   */
  void updateMaxPeers(uint32_t currentPeers);

  // Statistics query methods (thread-safe)
  
  /**
   * Get cumulative download bytes
   * @return Total bytes downloaded
   */
  uint64_t getDownloadBytes() const;

  /**
   * Get cumulative upload bytes
   * @return Total bytes uploaded
   */
  uint64_t getUploadBytes() const;

  /**
   * Get cumulative seed time in seconds
   * @return Total seconds spent seeding
   */
  uint64_t getSeedTimeSeconds() const;

  /**
   * Get maximum peer count observed
   * @return Maximum number of peers connected simultaneously
   */
  uint32_t getMaxPeers() const;

  // Initialization methods
  
  /**
   * Set all statistics at once (used for migration)
   * @param dlBytes Download bytes
   * @param ulBytes Upload bytes
   * @param seedSec Seed time in seconds
   * @param peers Maximum peer count
   */
  void setStatistics(uint64_t dlBytes, uint64_t ulBytes, 
                     uint64_t seedSec, uint32_t peers);

  /**
   * Check if statistics have been initialized
   * @return true if statistics are initialized, false otherwise
   */
  bool isInitialized() const;

private:
  // Storage format version
  static const uint32_t STORAGE_VERSION = 1;
  
  // Maximum safe uint64 value (to prevent overflow)
  static const uint64_t MAX_SAFE_UINT64 = UINT64_MAX - 1000000000ULL;

  // Binary storage format
  struct StorageFormat {
    uint32_t version;
    uint64_t downloadBytes;
    uint64_t uploadBytes;
    uint64_t seedTimeSeconds;
    uint32_t maxPeers;
    uint32_t checksum;
  } __attribute__((packed));

  // Member variables
  mutable std::mutex mutex_;
  uint64_t downloadBytes_;
  uint64_t uploadBytes_;
  uint64_t seedTimeSeconds_;
  uint32_t maxPeers_;
  bool initialized_;
  std::string storageFilePath_;

  // Internal methods
  
  /**
   * Initialize statistics to zero
   */
  void initializeDefaults();

  /**
   * Calculate CRC32 checksum
   * @param data Data to checksum
   * @param length Length of data
   * @return CRC32 checksum
   */
  uint32_t calculateChecksum(const uint8_t* data, size_t length) const;

  /**
   * Save statistics without acquiring lock (internal use only)
   */
  void saveInternal();
};

} // namespace aria2

#endif // D_BT_STATISTICS_MANAGER_H
