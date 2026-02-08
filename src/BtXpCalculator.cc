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
#include "BtXpCalculator.h"

#include <cmath>
#include <algorithm>

#include "BtStatisticsManager.h"

namespace aria2 {

// Level thresholds (XP required for each level)
const int BtXpCalculator::LEVEL_THRESHOLDS[] = {
  0,      // Lv1
  300,    // Lv2
  800,    // Lv3
  1600,   // Lv4
  3000,   // Lv5
  5200,   // Lv6
  8500,   // Lv7
  13000,  // Lv8
  20000   // Lv9
};

XpBreakdown BtXpCalculator::calculateXP(uint64_t dlBytes, uint64_t ulBytes,
                                         uint64_t seedSec, uint32_t peers)
{
  XpBreakdown xp;

  // Convert bytes to GB
  double dlGB = static_cast<double>(dlBytes) / (1024.0 * 1024.0 * 1024.0);
  double ulGB = static_cast<double>(ulBytes) / (1024.0 * 1024.0 * 1024.0);

  // Download XP: sqrt(GB) * 80
  xp.downloadXP = std::sqrt(dlGB) * 80.0;

  // Upload XP: sqrt(GB) * 150
  xp.uploadXP = std::sqrt(ulGB) * 150.0;

  // Share ratio bonus
  xp.ratioXP = calculateRatioBonus(dlBytes, ulBytes);

  // Peer XP: log10(1 + peers) * 200
  xp.peerXP = std::log10(1.0 + static_cast<double>(peers)) * 200.0;

  // Seed time XP: log2(1 + hours) * 100
  double seedHours = static_cast<double>(seedSec) / 3600.0;
  xp.timeXP = std::log2(1.0 + seedHours) * 100.0;

  // Total XP
  xp.totalXP = xp.downloadXP + xp.uploadXP + xp.ratioXP + xp.peerXP + xp.timeXP;

  return xp;
}

double BtXpCalculator::calculateRatioBonus(uint64_t dlBytes, uint64_t ulBytes)
{
  // Avoid division by zero
  if (dlBytes == 0) {
    return 0.0;
  }

  double dlGB = static_cast<double>(dlBytes) / (1024.0 * 1024.0 * 1024.0);
  double ulGB = static_cast<double>(ulBytes) / (1024.0 * 1024.0 * 1024.0);
  double ratio = ulGB / dlGB;

  // Apply thresholds
  if (ratio >= 5.0) {
    return 500.0;
  } else if (ratio >= 2.0) {
    return 300.0;
  } else if (ratio >= 1.0) {
    return 150.0;
  } else {
    return 0.0;
  }
}

int BtXpCalculator::determineLevel(double totalXP)
{
  // Find the highest level where XP >= threshold
  for (int i = NUM_LEVELS - 1; i >= 0; --i) {
    if (totalXP >= LEVEL_THRESHOLDS[i]) {
      return i + 1;  // Level is 1-indexed
    }
  }
  return 1;  // Default to level 1
}

int BtXpCalculator::getLevelThreshold(int level)
{
  if (level < 1 || level > NUM_LEVELS) {
    return 0;
  }
  return LEVEL_THRESHOLDS[level - 1];  // Convert 1-indexed to 0-indexed
}

LevelInfo BtXpCalculator::calculateLevel(const BtStatisticsManager& stats)
{
  LevelInfo info;

  // Get raw statistics
  info.downloadBytes = stats.getDownloadBytes();
  info.uploadBytes = stats.getUploadBytes();
  info.seedTimeSeconds = stats.getSeedTimeSeconds();
  info.maxPeers = stats.getMaxPeers();

  // Calculate XP
  info.xp = calculateXP(info.downloadBytes, info.uploadBytes,
                        info.seedTimeSeconds, info.maxPeers);

  // Determine level
  info.level = determineLevel(info.xp.totalXP);

  // Calculate share ratio
  if (info.downloadBytes > 0) {
    double dlGB = static_cast<double>(info.downloadBytes) / (1024.0 * 1024.0 * 1024.0);
    double ulGB = static_cast<double>(info.uploadBytes) / (1024.0 * 1024.0 * 1024.0);
    info.shareRatio = ulGB / dlGB;
  } else {
    info.shareRatio = 0.0;
  }

  // Calculate progress metrics
  info.currentLevelThreshold = getLevelThreshold(info.level);
  
  if (info.level < NUM_LEVELS) {
    info.nextLevelThreshold = getLevelThreshold(info.level + 1);
    info.xpToNextLevel = info.nextLevelThreshold - static_cast<int>(info.xp.totalXP);
  } else {
    // Max level reached
    info.nextLevelThreshold = info.currentLevelThreshold;
    info.xpToNextLevel = 0;
  }

  return info;
}

} // namespace aria2
