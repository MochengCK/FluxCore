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

#include <cppunit/extensions/HelperMacros.h>

#include "File.h"
#include "TestUtil.h"

namespace aria2 {

class BtStatisticsManagerTest : public CppUnit::TestFixture {
  CPPUNIT_TEST_SUITE(BtStatisticsManagerTest);
  CPPUNIT_TEST(testInitialization);
  CPPUNIT_TEST(testAddDownloadBytes);
  CPPUNIT_TEST(testAddUploadBytes);
  CPPUNIT_TEST(testAddSeedTime);
  CPPUNIT_TEST(testUpdateMaxPeers);
  CPPUNIT_TEST(testPersistenceRoundTrip);
  CPPUNIT_TEST(testCorruptedFileRecovery);
  CPPUNIT_TEST(testMissingFileHandling);
  CPPUNIT_TEST(testSetStatistics);
  CPPUNIT_TEST(testOverflowProtection);
  CPPUNIT_TEST_SUITE_END();

public:
  void setUp() override;
  void tearDown() override;

  void testInitialization();
  void testAddDownloadBytes();
  void testAddUploadBytes();
  void testAddSeedTime();
  void testUpdateMaxPeers();
  void testPersistenceRoundTrip();
  void testCorruptedFileRecovery();
  void testMissingFileHandling();
  void testSetStatistics();
  void testOverflowProtection();

private:
  std::string testFilePath_;
};

CPPUNIT_TEST_SUITE_REGISTRATION(BtStatisticsManagerTest);

void BtStatisticsManagerTest::setUp()
{
  testFilePath_ = A2_TEST_OUT_DIR "/bt-stats-test.dat";
  File(testFilePath_).remove();
}

void BtStatisticsManagerTest::tearDown()
{
  File(testFilePath_).remove();
}

void BtStatisticsManagerTest::testInitialization()
{
  BtStatisticsManager manager(testFilePath_);
  
  // Before load, should not be initialized
  CPPUNIT_ASSERT(!manager.isInitialized());
  
  // Load should initialize to zero
  manager.load();
  CPPUNIT_ASSERT(manager.isInitialized());
  CPPUNIT_ASSERT_EQUAL(static_cast<uint64_t>(0), manager.getDownloadBytes());
  CPPUNIT_ASSERT_EQUAL(static_cast<uint64_t>(0), manager.getUploadBytes());
  CPPUNIT_ASSERT_EQUAL(static_cast<uint64_t>(0), manager.getSeedTimeSeconds());
  CPPUNIT_ASSERT_EQUAL(static_cast<uint32_t>(0), manager.getMaxPeers());
}

void BtStatisticsManagerTest::testAddDownloadBytes()
{
  BtStatisticsManager manager(testFilePath_);
  manager.load();
  
  manager.addDownloadBytes(1024);
  CPPUNIT_ASSERT_EQUAL(static_cast<uint64_t>(1024), manager.getDownloadBytes());
  
  manager.addDownloadBytes(2048);
  CPPUNIT_ASSERT_EQUAL(static_cast<uint64_t>(3072), manager.getDownloadBytes());
}

void BtStatisticsManagerTest::testAddUploadBytes()
{
  BtStatisticsManager manager(testFilePath_);
  manager.load();
  
  manager.addUploadBytes(512);
  CPPUNIT_ASSERT_EQUAL(static_cast<uint64_t>(512), manager.getUploadBytes());
  
  manager.addUploadBytes(1024);
  CPPUNIT_ASSERT_EQUAL(static_cast<uint64_t>(1536), manager.getUploadBytes());
}

void BtStatisticsManagerTest::testAddSeedTime()
{
  BtStatisticsManager manager(testFilePath_);
  manager.load();
  
  manager.addSeedTime(60);
  CPPUNIT_ASSERT_EQUAL(static_cast<uint64_t>(60), manager.getSeedTimeSeconds());
  
  manager.addSeedTime(120);
  CPPUNIT_ASSERT_EQUAL(static_cast<uint64_t>(180), manager.getSeedTimeSeconds());
}

void BtStatisticsManagerTest::testUpdateMaxPeers()
{
  BtStatisticsManager manager(testFilePath_);
  manager.load();
  
  manager.updateMaxPeers(10);
  CPPUNIT_ASSERT_EQUAL(static_cast<uint32_t>(10), manager.getMaxPeers());
  
  // Lower value should not update
  manager.updateMaxPeers(5);
  CPPUNIT_ASSERT_EQUAL(static_cast<uint32_t>(10), manager.getMaxPeers());
  
  // Higher value should update
  manager.updateMaxPeers(20);
  CPPUNIT_ASSERT_EQUAL(static_cast<uint32_t>(20), manager.getMaxPeers());
}

void BtStatisticsManagerTest::testPersistenceRoundTrip()
{
  // Feature: bt-level-migration, Property 1: Statistics Persistence Round-Trip
  
  // Create manager and set statistics
  {
    BtStatisticsManager manager(testFilePath_);
    manager.load();
    
    manager.addDownloadBytes(1073741824ULL); // 1 GB
    manager.addUploadBytes(2147483648ULL);   // 2 GB
    manager.addSeedTime(3600);               // 1 hour
    manager.updateMaxPeers(50);
    
    manager.save();
  }
  
  // Load in new manager instance
  {
    BtStatisticsManager manager(testFilePath_);
    manager.load();
    
    CPPUNIT_ASSERT_EQUAL(static_cast<uint64_t>(1073741824ULL), manager.getDownloadBytes());
    CPPUNIT_ASSERT_EQUAL(static_cast<uint64_t>(2147483648ULL), manager.getUploadBytes());
    CPPUNIT_ASSERT_EQUAL(static_cast<uint64_t>(3600), manager.getSeedTimeSeconds());
    CPPUNIT_ASSERT_EQUAL(static_cast<uint32_t>(50), manager.getMaxPeers());
  }
}

void BtStatisticsManagerTest::testCorruptedFileRecovery()
{
  // Feature: bt-level-migration, Edge Case 1: Corrupted Storage Recovery
  
  // Create a corrupted file
  {
    std::ofstream ofs(testFilePath_, std::ios::binary);
    const char* garbage = "This is not a valid statistics file!";
    ofs.write(garbage, strlen(garbage));
  }
  
  // Manager should recover by initializing to zero
  BtStatisticsManager manager(testFilePath_);
  manager.load();
  
  CPPUNIT_ASSERT(manager.isInitialized());
  CPPUNIT_ASSERT_EQUAL(static_cast<uint64_t>(0), manager.getDownloadBytes());
  CPPUNIT_ASSERT_EQUAL(static_cast<uint64_t>(0), manager.getUploadBytes());
}

void BtStatisticsManagerTest::testMissingFileHandling()
{
  // File doesn't exist - should initialize to zero
  BtStatisticsManager manager(testFilePath_);
  manager.load();
  
  CPPUNIT_ASSERT(manager.isInitialized());
  CPPUNIT_ASSERT_EQUAL(static_cast<uint64_t>(0), manager.getDownloadBytes());
}

void BtStatisticsManagerTest::testSetStatistics()
{
  BtStatisticsManager manager(testFilePath_);
  manager.load();
  
  manager.setStatistics(
    10737418240ULL,  // 10 GB download
    21474836480ULL,  // 20 GB upload
    7200,            // 2 hours seed time
    100              // 100 max peers
  );
  
  CPPUNIT_ASSERT_EQUAL(static_cast<uint64_t>(10737418240ULL), manager.getDownloadBytes());
  CPPUNIT_ASSERT_EQUAL(static_cast<uint64_t>(21474836480ULL), manager.getUploadBytes());
  CPPUNIT_ASSERT_EQUAL(static_cast<uint64_t>(7200), manager.getSeedTimeSeconds());
  CPPUNIT_ASSERT_EQUAL(static_cast<uint32_t>(100), manager.getMaxPeers());
}

void BtStatisticsManagerTest::testOverflowProtection()
{
  // Feature: bt-level-migration, Edge Case 6: Statistics Overflow
  
  BtStatisticsManager manager(testFilePath_);
  manager.load();
  
  // Set to near maximum
  uint64_t nearMax = UINT64_MAX - 1000000000ULL;
  manager.setStatistics(nearMax, nearMax, nearMax, 1000);
  
  // Try to add more - should cap at maximum
  manager.addDownloadBytes(2000000000ULL);
  manager.addUploadBytes(2000000000ULL);
  manager.addSeedTime(2000000000ULL);
  
  // Should be capped, not overflowed
  CPPUNIT_ASSERT(manager.getDownloadBytes() < UINT64_MAX);
  CPPUNIT_ASSERT(manager.getUploadBytes() < UINT64_MAX);
  CPPUNIT_ASSERT(manager.getSeedTimeSeconds() < UINT64_MAX);
}

} // namespace aria2
