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

#include <cppunit/extensions/HelperMacros.h>
#include <cmath>

#include "BtStatisticsManager.h"
#include "TestUtil.h"

namespace aria2 {

class BtXpCalculatorTest : public CppUnit::TestFixture {
  CPPUNIT_TEST_SUITE(BtXpCalculatorTest);
  CPPUNIT_TEST(testDownloadXpFormula);
  CPPUNIT_TEST(testUploadXpFormula);
  CPPUNIT_TEST(testPeerXpFormula);
  CPPUNIT_TEST(testTimeXpFormula);
  CPPUNIT_TEST(testShareRatioBonusThresholds);
  CPPUNIT_TEST(testZeroDownloadShareRatio);
  CPPUNIT_TEST(testTotalXpIsSumOfComponents);
  CPPUNIT_TEST(testLevelDetermination);
  CPPUNIT_TEST(testLevelThresholds);
  CPPUNIT_TEST(testProgressCalculations);
  CPPUNIT_TEST(testMaxLevelProgress);
  CPPUNIT_TEST(testCompleteCalculation);
  CPPUNIT_TEST_SUITE_END();

public:
  void setUp() override;
  void tearDown() override;

  void testDownloadXpFormula();
  void testUploadXpFormula();
  void testPeerXpFormula();
  void testTimeXpFormula();
  void testShareRatioBonusThresholds();
  void testZeroDownloadShareRatio();
  void testTotalXpIsSumOfComponents();
  void testLevelDetermination();
  void testLevelThresholds();
  void testProgressCalculations();
  void testMaxLevelProgress();
  void testCompleteCalculation();

private:
  std::string testFilePath_;
  
  // Helper to compare doubles with tolerance
  void assertDoubleEqual(double expected, double actual, double tolerance = 0.01) {
    CPPUNIT_ASSERT(std::abs(expected - actual) < tolerance);
  }
};

CPPUNIT_TEST_SUITE_REGISTRATION(BtXpCalculatorTest);

void BtXpCalculatorTest::setUp()
{
  testFilePath_ = A2_TEST_OUT_DIR "/bt-xp-test.dat";
}

void BtXpCalculatorTest::tearDown()
{
}

void BtXpCalculatorTest::testDownloadXpFormula()
{
  // Feature: bt-level-migration, Property 2: XP Component Calculations
  
  BtStatisticsManager stats(testFilePath_);
  stats.load();
  
  // 1 GB download = sqrt(1) * 80 = 80 XP
  stats.setStatistics(1073741824ULL, 0, 0, 0);
  LevelInfo info = BtXpCalculator::calculateLevel(stats);
  assertDoubleEqual(80.0, info.xp.downloadXP);
  
  // 10 GB download = sqrt(10) * 80 ≈ 253 XP
  stats.setStatistics(10737418240ULL, 0, 0, 0);
  info = BtXpCalculator::calculateLevel(stats);
  assertDoubleEqual(253.0, info.xp.downloadXP, 1.0);
  
  // 100 GB download = sqrt(100) * 80 = 800 XP
  stats.setStatistics(107374182400ULL, 0, 0, 0);
  info = BtXpCalculator::calculateLevel(stats);
  assertDoubleEqual(800.0, info.xp.downloadXP);
}

void BtXpCalculatorTest::testUploadXpFormula()
{
  // Feature: bt-level-migration, Property 2: XP Component Calculations
  
  BtStatisticsManager stats(testFilePath_);
  stats.load();
  
  // 1 GB upload = sqrt(1) * 150 = 150 XP
  stats.setStatistics(0, 1073741824ULL, 0, 0);
  LevelInfo info = BtXpCalculator::calculateLevel(stats);
  assertDoubleEqual(150.0, info.xp.uploadXP);
  
  // 10 GB upload = sqrt(10) * 150 ≈ 474 XP
  stats.setStatistics(0, 10737418240ULL, 0, 0);
  info = BtXpCalculator::calculateLevel(stats);
  assertDoubleEqual(474.0, info.xp.uploadXP, 1.0);
  
  // 100 GB upload = sqrt(100) * 150 = 1500 XP
  stats.setStatistics(0, 107374182400ULL, 0, 0);
  info = BtXpCalculator::calculateLevel(stats);
  assertDoubleEqual(1500.0, info.xp.uploadXP);
}

void BtXpCalculatorTest::testPeerXpFormula()
{
  // Feature: bt-level-migration, Property 2: XP Component Calculations
  
  BtStatisticsManager stats(testFilePath_);
  stats.load();
  
  // 10 peers = log10(11) * 200 ≈ 208 XP
  stats.setStatistics(0, 0, 0, 10);
  LevelInfo info = BtXpCalculator::calculateLevel(stats);
  assertDoubleEqual(208.0, info.xp.peerXP, 2.0);
  
  // 100 peers = log10(101) * 200 ≈ 402 XP
  stats.setStatistics(0, 0, 0, 100);
  info = BtXpCalculator::calculateLevel(stats);
  assertDoubleEqual(402.0, info.xp.peerXP, 2.0);
  
  // 1000 peers = log10(1001) * 200 ≈ 600 XP
  stats.setStatistics(0, 0, 0, 1000);
  info = BtXpCalculator::calculateLevel(stats);
  assertDoubleEqual(600.0, info.xp.peerXP, 2.0);
}

void BtXpCalculatorTest::testTimeXpFormula()
{
  // Feature: bt-level-migration, Property 2: XP Component Calculations
  
  BtStatisticsManager stats(testFilePath_);
  stats.load();
  
  // 1 hour = log2(2) * 100 = 100 XP
  stats.setStatistics(0, 0, 3600, 0);
  LevelInfo info = BtXpCalculator::calculateLevel(stats);
  assertDoubleEqual(100.0, info.xp.timeXP);
  
  // 10 hours = log2(11) * 100 ≈ 346 XP
  stats.setStatistics(0, 0, 36000, 0);
  info = BtXpCalculator::calculateLevel(stats);
  assertDoubleEqual(346.0, info.xp.timeXP, 2.0);
  
  // 100 hours = log2(101) * 100 ≈ 664 XP
  stats.setStatistics(0, 0, 360000, 0);
  info = BtXpCalculator::calculateLevel(stats);
  assertDoubleEqual(664.0, info.xp.timeXP, 2.0);
}

void BtXpCalculatorTest::testShareRatioBonusThresholds()
{
  // Feature: bt-level-migration, Property 3: Share Ratio Bonus Thresholds
  
  BtStatisticsManager stats(testFilePath_);
  stats.load();
  
  uint64_t oneGB = 1073741824ULL;
  
  // Ratio < 1.0: 0 XP
  stats.setStatistics(oneGB * 2, oneGB, 0, 0);  // Ratio = 0.5
  LevelInfo info = BtXpCalculator::calculateLevel(stats);
  assertDoubleEqual(0.0, info.xp.ratioXP);
  
  // Ratio >= 1.0 and < 2.0: 150 XP
  stats.setStatistics(oneGB, oneGB * 1.5, 0, 0);  // Ratio = 1.5
  info = BtXpCalculator::calculateLevel(stats);
  assertDoubleEqual(150.0, info.xp.ratioXP);
  
  // Ratio >= 2.0 and < 5.0: 300 XP
  stats.setStatistics(oneGB, oneGB * 3, 0, 0);  // Ratio = 3.0
  info = BtXpCalculator::calculateLevel(stats);
  assertDoubleEqual(300.0, info.xp.ratioXP);
  
  // Ratio >= 5.0: 500 XP
  stats.setStatistics(oneGB, oneGB * 10, 0, 0);  // Ratio = 10.0
  info = BtXpCalculator::calculateLevel(stats);
  assertDoubleEqual(500.0, info.xp.ratioXP);
}

void BtXpCalculatorTest::testZeroDownloadShareRatio()
{
  // Feature: bt-level-migration, Edge Case 2: Zero Download Bytes
  
  BtStatisticsManager stats(testFilePath_);
  stats.load();
  
  // Zero download, any upload = ratio 0, bonus 0
  stats.setStatistics(0, 1073741824ULL, 0, 0);
  LevelInfo info = BtXpCalculator::calculateLevel(stats);
  
  assertDoubleEqual(0.0, info.shareRatio);
  assertDoubleEqual(0.0, info.xp.ratioXP);
}

void BtXpCalculatorTest::testTotalXpIsSumOfComponents()
{
  // Feature: bt-level-migration, Property 4: Total XP is Sum of Components
  
  BtStatisticsManager stats(testFilePath_);
  stats.load();
  
  // Set various statistics
  stats.setStatistics(
    10737418240ULL,  // 10 GB download
    21474836480ULL,  // 20 GB upload (ratio = 2.0)
    36000,           // 10 hours seed time
    100              // 100 peers
  );
  
  LevelInfo info = BtXpCalculator::calculateLevel(stats);
  
  double expectedTotal = info.xp.downloadXP + info.xp.uploadXP + 
                         info.xp.ratioXP + info.xp.peerXP + info.xp.timeXP;
  
  assertDoubleEqual(expectedTotal, info.xp.totalXP);
}

void BtXpCalculatorTest::testLevelDetermination()
{
  // Feature: bt-level-migration, Property 5: Level Determination from XP
  
  BtStatisticsManager stats(testFilePath_);
  stats.load();
  
  // Test each level threshold
  struct TestCase {
    uint64_t downloadBytes;
    int expectedLevel;
  };
  
  TestCase cases[] = {
    {0, 1},                      // 0 XP = Lv1
    {14073748480ULL, 2},         // ~300 XP = Lv2
    {107374182400ULL, 3},        // ~800 XP = Lv3
    {429496729600ULL, 4},        // ~1600 XP = Lv4
    {1503238553600ULL, 5},       // ~3000 XP = Lv5
    {4503238553600ULL, 6},       // ~5200 XP = Lv6
    {12003238553600ULL, 7},      // ~8500 XP = Lv7
    {28003238553600ULL, 8},      // ~13000 XP = Lv8
    {68003238553600ULL, 9}       // ~20000 XP = Lv9
  };
  
  for (const auto& tc : cases) {
    stats.setStatistics(tc.downloadBytes, 0, 0, 0);
    LevelInfo info = BtXpCalculator::calculateLevel(stats);
    CPPUNIT_ASSERT_EQUAL(tc.expectedLevel, info.level);
  }
}

void BtXpCalculatorTest::testLevelThresholds()
{
  // Verify getLevelThreshold returns correct values
  CPPUNIT_ASSERT_EQUAL(0, BtXpCalculator::getLevelThreshold(1));
  CPPUNIT_ASSERT_EQUAL(300, BtXpCalculator::getLevelThreshold(2));
  CPPUNIT_ASSERT_EQUAL(800, BtXpCalculator::getLevelThreshold(3));
  CPPUNIT_ASSERT_EQUAL(1600, BtXpCalculator::getLevelThreshold(4));
  CPPUNIT_ASSERT_EQUAL(3000, BtXpCalculator::getLevelThreshold(5));
  CPPUNIT_ASSERT_EQUAL(5200, BtXpCalculator::getLevelThreshold(6));
  CPPUNIT_ASSERT_EQUAL(8500, BtXpCalculator::getLevelThreshold(7));
  CPPUNIT_ASSERT_EQUAL(13000, BtXpCalculator::getLevelThreshold(8));
  CPPUNIT_ASSERT_EQUAL(20000, BtXpCalculator::getLevelThreshold(9));
}

void BtXpCalculatorTest::testProgressCalculations()
{
  // Feature: bt-level-migration, Property 7: Progress Calculations
  
  BtStatisticsManager stats(testFilePath_);
  stats.load();
  
  // Set to mid-level 3 (between 800 and 1600 XP)
  stats.setStatistics(107374182400ULL, 0, 0, 0);  // ~800 XP
  LevelInfo info = BtXpCalculator::calculateLevel(stats);
  
  CPPUNIT_ASSERT_EQUAL(3, info.level);
  CPPUNIT_ASSERT_EQUAL(800, info.currentLevelThreshold);
  CPPUNIT_ASSERT_EQUAL(1600, info.nextLevelThreshold);
  CPPUNIT_ASSERT(info.xpToNextLevel > 0);
  CPPUNIT_ASSERT(info.xpToNextLevel <= 800);  // Should be within range
}

void BtXpCalculatorTest::testMaxLevelProgress()
{
  // Test progress at max level
  BtStatisticsManager stats(testFilePath_);
  stats.load();
  
  // Set to well above Lv9 threshold
  stats.setStatistics(1000000000000ULL, 0, 0, 0);  // Huge amount
  LevelInfo info = BtXpCalculator::calculateLevel(stats);
  
  CPPUNIT_ASSERT_EQUAL(9, info.level);
  CPPUNIT_ASSERT_EQUAL(20000, info.currentLevelThreshold);
  CPPUNIT_ASSERT_EQUAL(20000, info.nextLevelThreshold);  // Same as current
  CPPUNIT_ASSERT_EQUAL(0, info.xpToNextLevel);  // No next level
}

void BtXpCalculatorTest::testCompleteCalculation()
{
  // Integration test with realistic values
  BtStatisticsManager stats(testFilePath_);
  stats.load();
  
  // Realistic scenario: moderate user
  stats.setStatistics(
    53687091200ULL,   // 50 GB download
    107374182400ULL,  // 100 GB upload (ratio = 2.0)
    86400,            // 24 hours seed time
    75                // 75 max peers
  );
  
  LevelInfo info = BtXpCalculator::calculateLevel(stats);
  
  // Verify all fields are populated
  CPPUNIT_ASSERT(info.level >= 1 && info.level <= 9);
  CPPUNIT_ASSERT(info.xp.totalXP > 0);
  CPPUNIT_ASSERT(info.xp.downloadXP > 0);
  CPPUNIT_ASSERT(info.xp.uploadXP > 0);
  CPPUNIT_ASSERT(info.xp.ratioXP > 0);  // Ratio >= 2.0
  CPPUNIT_ASSERT(info.xp.peerXP > 0);
  CPPUNIT_ASSERT(info.xp.timeXP > 0);
  CPPUNIT_ASSERT_EQUAL(static_cast<uint64_t>(53687091200ULL), info.downloadBytes);
  CPPUNIT_ASSERT_EQUAL(static_cast<uint64_t>(107374182400ULL), info.uploadBytes);
  CPPUNIT_ASSERT(info.shareRatio > 1.9 && info.shareRatio < 2.1);
  CPPUNIT_ASSERT(info.currentLevelThreshold >= 0);
  CPPUNIT_ASSERT(info.nextLevelThreshold >= info.currentLevelThreshold);
}

} // namespace aria2
