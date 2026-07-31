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
class SocketCore;
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

class Ed2kHelper {
public:
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
  
  // Get default ED2K servers
  static void getDefaultServers(std::vector<Ed2kServerEntry>& servers);
  
  // Send ED2K login handshake
  static bool sendLoginHandshake(const std::shared_ptr<SocketCore>& socket, const std::shared_ptr<Option>& option);
  
  // Search for a file on an ED2K server
  static bool searchFile(const std::shared_ptr<SocketCore>& socket, const Ed2kFileInfo& fileInfo);
  
  // Get file sources from an ED2K server
  static bool getFileSources(const std::shared_ptr<SocketCore>& socket, const Ed2kFileInfo& fileInfo, std::vector<Ed2kSourceEntry>& sources);
};

} // namespace aria2

#endif // D_ED2K_HELPER_H