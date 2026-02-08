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
#include "BtStatisticsManager.h"

#include <fstream>
#include <cstring>
#include <algorithm>

#include "LogFactory.h"
#include "Logger.h"
#include "util.h"
#include "File.h"

namespace aria2 {

BtStatisticsManager::BtStatisticsManager(const std::string& storageFilePath)
  : downloadBytes_(0),
    uploadBytes_(0),
    seedTimeSeconds_(0),
    maxPeers_(0),
    initialized_(false),
    storageFilePath_(storageFilePath)
{
}

BtStatisticsManager::~BtStatisticsManager()
{
}

void BtStatisticsManager::initializeDefaults()
{
  downloadBytes_ = 0;
  uploadBytes_ = 0;
  seedTimeSeconds_ = 0;
  maxPeers_ = 0;
  initialized_ = true;
}

uint32_t BtStatisticsManager::calculateChecksum(const uint8_t* data, size_t length) const
{
  // CRC32 implementation
  uint32_t crc = 0xFFFFFFFF;
  for (size_t i = 0; i < length; i++) {
    crc ^= data[i];
    for (int j = 0; j < 8; j++) {
      crc = (crc >> 1) ^ (0xEDB88320 & -(crc & 1));
    }
  }
  return ~crc;
}

void BtStatisticsManager::load()
{
  std::lock_guard<std::mutex> lock(mutex_);
  
  try {
    File file(storageFilePath_);
    
    if (!file.exists()) {
      A2_LOG_INFO(fmt("BT statistics file does not exist, initializing to zero: %s",
                      storageFilePath_.c_str()));
      initializeDefaults();
      return;
    }

    std::ifstream ifs(storageFilePath_, std::ios::binary);
    if (!ifs.is_open()) {
      A2_LOG_WARN(fmt("Failed to open BT statistics file: %s",
                      storageFilePath_.c_str()));
      initializeDefaults();
      return;
    }

    // Read storage format
    StorageFormat data;
    ifs.read(reinterpret_cast<char*>(&data), sizeof(data));
    
    if (!ifs.good() || ifs.gcount() != sizeof(data)) {
      A2_LOG_WARN(fmt("BT statistics file corrupted (incomplete read): %s",
                      storageFilePath_.c_str()));
      initializeDefaults();
      return;
    }

    // Verify checksum
    uint32_t computed = calculateChecksum(
      reinterpret_cast<const uint8_t*>(&data),
      sizeof(data) - sizeof(data.checksum)
    );

    if (computed != data.checksum) {
      A2_LOG_WARN(fmt("BT statistics file corrupted (checksum mismatch): %s",
                      storageFilePath_.c_str()));
      initializeDefaults();
      return;
    }

    // Verify version
    if (data.version != STORAGE_VERSION) {
      A2_LOG_INFO(fmt("BT statistics version mismatch (file: %u, current: %u), "
                      "initializing to zero: %s",
                      data.version, STORAGE_VERSION, storageFilePath_.c_str()));
      initializeDefaults();
      return;
    }

    // Load data
    downloadBytes_ = data.downloadBytes;
    uploadBytes_ = data.uploadBytes;
    seedTimeSeconds_ = data.seedTimeSeconds;
    maxPeers_ = data.maxPeers;
    initialized_ = true;

    A2_LOG_INFO(fmt("Loaded BT statistics: DL=%s, UL=%s, SeedTime=%lus, MaxPeers=%u",
                    util::abbrevSize(downloadBytes_).c_str(),
                    util::abbrevSize(uploadBytes_).c_str(),
                    static_cast<unsigned long>(seedTimeSeconds_),
                    maxPeers_));

  } catch (const std::exception& e) {
    A2_LOG_ERROR(fmt("Failed to load BT statistics: %s", e.what()));
    initializeDefaults();
  }
}

void BtStatisticsManager::saveInternal()
{
  try {
    // Prepare data
    StorageFormat data;
    std::memset(&data, 0, sizeof(data));
    
    data.version = STORAGE_VERSION;
    data.downloadBytes = downloadBytes_;
    data.uploadBytes = uploadBytes_;
    data.seedTimeSeconds = seedTimeSeconds_;
    data.maxPeers = maxPeers_;
    
    // Calculate checksum
    data.checksum = calculateChecksum(
      reinterpret_cast<const uint8_t*>(&data),
      sizeof(data) - sizeof(data.checksum)
    );

    // Atomic write: write to temp file, then rename
    std::string tempPath = storageFilePath_ + ".tmp";
    
    std::ofstream ofs(tempPath, std::ios::binary | std::ios::trunc);
    if (!ofs.is_open()) {
      throw std::runtime_error("Failed to open temp file for writing");
    }

    ofs.write(reinterpret_cast<const char*>(&data), sizeof(data));
    ofs.close();

    if (!ofs.good()) {
      throw std::runtime_error("Failed to write to temp file");
    }

    // Atomic rename
    File tempFile(tempPath);
    if (!tempFile.renameTo(storageFilePath_)) {
      throw std::runtime_error("Failed to rename temp file");
    }

    A2_LOG_DEBUG(fmt("Saved BT statistics: DL=%s, UL=%s, SeedTime=%lus, MaxPeers=%u",
                     util::abbrevSize(downloadBytes_).c_str(),
                     util::abbrevSize(uploadBytes_).c_str(),
                     static_cast<unsigned long>(seedTimeSeconds_),
                     maxPeers_));

  } catch (const std::exception& e) {
    A2_LOG_ERROR(fmt("Failed to save BT statistics: %s", e.what()));
    // Don't throw - allow engine to continue running
  }
}

void BtStatisticsManager::save()
{
  std::lock_guard<std::mutex> lock(mutex_);
  saveInternal();
}

void BtStatisticsManager::addDownloadBytes(uint64_t bytes)
{
  std::lock_guard<std::mutex> lock(mutex_);
  
  // Check for overflow
  if (downloadBytes_ > MAX_SAFE_UINT64 - bytes) {
    A2_LOG_WARN("Download bytes would overflow, capping at maximum");
    downloadBytes_ = MAX_SAFE_UINT64;
  } else {
    downloadBytes_ += bytes;
  }
}

void BtStatisticsManager::addUploadBytes(uint64_t bytes)
{
  std::lock_guard<std::mutex> lock(mutex_);
  
  // Check for overflow
  if (uploadBytes_ > MAX_SAFE_UINT64 - bytes) {
    A2_LOG_WARN("Upload bytes would overflow, capping at maximum");
    uploadBytes_ = MAX_SAFE_UINT64;
  } else {
    uploadBytes_ += bytes;
  }
}

void BtStatisticsManager::addSeedTime(uint32_t seconds)
{
  std::lock_guard<std::mutex> lock(mutex_);
  
  // Check for overflow
  if (seedTimeSeconds_ > MAX_SAFE_UINT64 - seconds) {
    A2_LOG_WARN("Seed time would overflow, capping at maximum");
    seedTimeSeconds_ = MAX_SAFE_UINT64;
  } else {
    seedTimeSeconds_ += seconds;
  }
}

void BtStatisticsManager::updateMaxPeers(uint32_t currentPeers)
{
  std::lock_guard<std::mutex> lock(mutex_);
  
  if (currentPeers > maxPeers_) {
    maxPeers_ = currentPeers;
  }
}

uint64_t BtStatisticsManager::getDownloadBytes() const
{
  std::lock_guard<std::mutex> lock(mutex_);
  return downloadBytes_;
}

uint64_t BtStatisticsManager::getUploadBytes() const
{
  std::lock_guard<std::mutex> lock(mutex_);
  return uploadBytes_;
}

uint64_t BtStatisticsManager::getSeedTimeSeconds() const
{
  std::lock_guard<std::mutex> lock(mutex_);
  return seedTimeSeconds_;
}

uint32_t BtStatisticsManager::getMaxPeers() const
{
  std::lock_guard<std::mutex> lock(mutex_);
  return maxPeers_;
}

void BtStatisticsManager::setStatistics(uint64_t dlBytes, uint64_t ulBytes,
                                        uint64_t seedSec, uint32_t peers)
{
  std::lock_guard<std::mutex> lock(mutex_);
  
  downloadBytes_ = std::min(dlBytes, MAX_SAFE_UINT64);
  uploadBytes_ = std::min(ulBytes, MAX_SAFE_UINT64);
  seedTimeSeconds_ = std::min(seedSec, MAX_SAFE_UINT64);
  maxPeers_ = peers;
  initialized_ = true;
  
  A2_LOG_INFO(fmt("Set BT statistics: DL=%s, UL=%s, SeedTime=%lus, MaxPeers=%u",
                  util::abbrevSize(downloadBytes_).c_str(),
                  util::abbrevSize(uploadBytes_).c_str(),
                  static_cast<unsigned long>(seedTimeSeconds_),
                  maxPeers_));
}

bool BtStatisticsManager::isInitialized() const
{
  std::lock_guard<std::mutex> lock(mutex_);
  return initialized_;
}

} // namespace aria2
