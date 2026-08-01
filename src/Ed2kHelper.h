/* <!-- copyright */
/*
 * aria2 - The high speed download utility
 *
 * Copyright (C) 2015 Tatsuhiro Tsujikawa
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
#ifndef D_ED2K_HELPER_H
#define D_ED2K_HELPER_H

#include "common.h"

#include <string>
#include <vector>
#include <memory>

namespace aria2 {
class Option;

struct Ed2kLinkInfo {
  std::string name;
  uint64_t size;
  std::string hash;  // MD4 hash in hex
  std::vector<std::string> serverUris;  // ed2k server URIs
};

struct Ed2kServerEntry {
  std::string addr;
  uint16_t port;
};

struct Ed2kSourceEntry {
  std::string addr;
  uint16_t port;
  std::string clientId;
};

struct Ed2kFileInfo {
  std::string filename;
  uint64_t filesize;
  std::string filehash;
  std::string serverAddr;
  uint16_t serverPort;
  std::vector<std::string> partHashes;
};

// Streaming MD4 context (RFC 1320) used for ED2K part/file hashing.
// The ED2K file hash is computed as follows:
//   - Split the file into 9.5MB (9,728,000 byte = 9500 KiB) parts.
//   - If there is more than one part, the file hash is MD4 of the
//     concatenation of all part MD4 digests.
//   - If the file fits in a single part, the file hash is that part's MD4.
class Ed2kMd4 {
public:
  Ed2kMd4();
  ~Ed2kMd4();
  void update(const unsigned char* data, size_t length);
  // Writes the 16-byte digest and resets the context for reuse.
  void final(unsigned char* digest);
  // Convenience: hex digest of the current state (also resets).
  std::string finalHex();

private:
  struct Impl;
  std::unique_ptr<Impl> impl_;
};

class Ed2kHelper {
public:
  // ED2K part size used by the MD4 hash tree (9,728,000 bytes = 9500 KiB).
  // This is eMule's PARTSIZE constant — getting it wrong breaks the MD4
  // part hashing and therefore whole-file verification.
  static constexpr int64_t PART_SIZE = 9728000;

  // Parse an ed2k:// link, return parsed info or nullptr if invalid
  static std::unique_ptr<Ed2kLinkInfo> parseLink(const std::string& uri);
  
  // Check if a URI is an ED2K link
  static bool isEd2kLink(const std::string& uri);
  
  // Check if a URI is an ED2K server URI
  static bool isEd2kServerUri(const std::string& uri);
  
  // Compute MD4 hash of data
  static std::string computeMd4(const unsigned char* data, size_t length);
  
  // Format hash bytes to hex string
  static std::string hashToHex(const unsigned char* hash, size_t length);
  
  // Parse hex string to hash bytes
  static std::vector<unsigned char> hexToHash(const std::string& hex);
  
  // Get default ED2K server ports
  static const std::vector<uint16_t>& getDefaultServerPorts();
  
  // Get default ED2K client ports
  static const std::vector<uint16_t>& getDefaultClientPorts();
  
  // Parse ED2K link into Ed2kFileInfo struct
  static bool parseLink(const std::string& uri, Ed2kFileInfo& info);
  
  // Get default ED2K servers. If opt is provided and ed2k-default-servers
  // is configured, parse that list; otherwise fall back to built-in defaults.
  static void getDefaultServers(std::vector<Ed2kServerEntry>& servers,
                                 const Option* opt = nullptr);

  // Parse user-configured ED2K server list (comma-separated host:port).
  static void parseDefaultServers(const std::string& config,
                                   std::vector<Ed2kServerEntry>& servers);

  // Get default KAD (Kademlia) bootstrap nodes for source discovery.
  // These are well-known KAD nodes used to bootstrap the DHT network.
  static void getDefaultKadBootstrapNodes(std::vector<Ed2kServerEntry>& nodes);

  // Parse user-configured KAD bootstrap node list (comma-separated host:port).
  static void parseKadBootstrapNodes(const std::string& config,
                                     std::vector<Ed2kServerEntry>& nodes);
};

} // namespace aria2

#endif // D_ED2K_HELPER_H