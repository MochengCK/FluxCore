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
#ifndef D_BT_XP_CALCULATOR_H
#define D_BT_XP_CALCULATOR_H

#include "common.h"

#include <cstdint>

namespace aria2 {

class BtStatisticsManager;

/**
 * XP breakdown structure containing individual XP components
 */
struct XpBreakdown {
  double downloadXP;      // XP from download volume
  double uploadXP;        // XP from upload volume
  double ratioXP;         // Bonus XP from share ratio
  double peerXP;          // XP from peer connections
  double timeXP;          // XP from seed time
  double totalXP;         // Sum of all XP components
};

/**
 * Complete level information including XP breakdown and statistics
 */
struct LevelInfo {
  int level;                      // Current level (1-9)
  XpBreakdown xp;                 // XP breakdown
  uint64_t downloadBytes;         // Total download bytes
  uint64_t uploadBytes;           // Total upload bytes
  uint64_t seedTimeSeconds;       // Total seed time in seconds
  uint32_t maxPeers;              // Maximum peer count
  double shareRatio;              // Upload/download ratio
  int currentLevelThreshold;      // XP threshold for current level
  int nextLevelThreshold;         // XP threshold for next level
  int xpToNextLevel;              // XP needed to reach next level
};

/**
 * BtXpCalculator calculates experience points (XP) and determines
 * BitTorrent user level based on activity statistics.
 * 
 * XP is calculated from:
 * - Download volume: sqrt(GB) * 80
 * - Upload volume: sqrt(GB) * 150
 * - Share ratio bonus: 150-500 XP based on thresholds
 * - Peer connections: log10(1 + peers) * 200
 * - Seed time: log2(1 + hours) * 100
 * 
 * Levels range from 1 to 9 with increasing XP thresholds.
 */
class BtXpCalculator {
public:
  /**
   * Calculate complete level information from statistics
   * @param stats Statistics manager containing raw data
   * @return LevelInfo structure with level, XP breakdown, and progress
   */
  static LevelInfo calculateLevel(const BtStatisticsManager& stats);

  /**
   * Get XP threshold for a specific level
   * @param level Level number (1-9)
   * @return Minimum XP required for that level
   */
  static int getLevelThreshold(int level);

private:
  /**
   * Calculate XP breakdown from raw statistics
   * @param dlBytes Download bytes
   * @param ulBytes Upload bytes
   * @param seedSec Seed time in seconds
   * @param peers Maximum peer count
   * @return XpBreakdown with all components calculated
   */
  static XpBreakdown calculateXP(uint64_t dlBytes, uint64_t ulBytes,
                                  uint64_t seedSec, uint32_t peers);

  /**
   * Determine level from total XP
   * @param totalXP Total experience points
   * @return Level number (1-9)
   */
  static int determineLevel(double totalXP);

  /**
   * Calculate share ratio bonus XP
   * @param dlBytes Download bytes
   * @param ulBytes Upload bytes
   * @return Bonus XP based on ratio thresholds
   */
  static double calculateRatioBonus(uint64_t dlBytes, uint64_t ulBytes);

  // Level thresholds
  static const int LEVEL_THRESHOLDS[];
  static const int NUM_LEVELS = 9;
};

} // namespace aria2

#endif // D_BT_XP_CALCULATOR_H
