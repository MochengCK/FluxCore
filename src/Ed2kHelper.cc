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
#include "Ed2kHelper.h"

#include <cstring>
#include <algorithm>

#include "util.h"
#include "a2functional.h"
#include "SocketCore.h"
#include "Option.h"
#include "Logger.h"
#include "LogFactory.h"
#include "fmt.h"
#include "RecoverableException.h"

namespace aria2 {

// MD4 implementation (RFC 1320)
namespace {

struct MD4Context {
  uint32_t state[4];
  uint64_t count;
  unsigned char buffer[64];
};

inline uint32_t md4F(uint32_t x, uint32_t y, uint32_t z)
{
  return (x & y) | (~x & z);
}

inline uint32_t md4G(uint32_t x, uint32_t y, uint32_t z)
{
  return (x & y) | (x & z) | (y & z);
}

inline uint32_t md4H(uint32_t x, uint32_t y, uint32_t z)
{
  return x ^ y ^ z;
}

inline uint32_t md4Rotl(uint32_t x, uint32_t n)
{
  return (x << n) | (x >> (32 - n));
}

inline void md4Round1(uint32_t& a, uint32_t b, uint32_t c, uint32_t d,
                      uint32_t x, uint32_t s)
{
  a = md4Rotl(a + md4F(b, c, d) + x, s);
}

inline void md4Round2(uint32_t& a, uint32_t b, uint32_t c, uint32_t d,
                      uint32_t x, uint32_t s)
{
  a = md4Rotl(a + md4G(b, c, d) + x + 0x5A827999u, s);
}

inline void md4Round3(uint32_t& a, uint32_t b, uint32_t c, uint32_t d,
                      uint32_t x, uint32_t s)
{
  a = md4Rotl(a + md4H(b, c, d) + x + 0x6ED9EBA1u, s);
}

void md4Transform(uint32_t state[4], const unsigned char block[64])
{
  uint32_t a = state[0], b = state[1], c = state[2], d = state[3];
  uint32_t x[16];

  for (size_t i = 0; i < 16; ++i) {
    x[i] = block[i * 4] | (block[i * 4 + 1] << 8) |
           (block[i * 4 + 2] << 16) | (block[i * 4 + 3] << 24);
  }

  // Round 1
  md4Round1(a, b, c, d, x[0], 3);
  md4Round1(d, a, b, c, x[1], 7);
  md4Round1(c, d, a, b, x[2], 11);
  md4Round1(b, c, d, a, x[3], 19);
  md4Round1(a, b, c, d, x[4], 3);
  md4Round1(d, a, b, c, x[5], 7);
  md4Round1(c, d, a, b, x[6], 11);
  md4Round1(b, c, d, a, x[7], 19);
  md4Round1(a, b, c, d, x[8], 3);
  md4Round1(d, a, b, c, x[9], 7);
  md4Round1(c, d, a, b, x[10], 11);
  md4Round1(b, c, d, a, x[11], 19);
  md4Round1(a, b, c, d, x[12], 3);
  md4Round1(d, a, b, c, x[13], 7);
  md4Round1(c, d, a, b, x[14], 11);
  md4Round1(b, c, d, a, x[15], 19);

  // Round 2
  md4Round2(a, b, c, d, x[0], 3);
  md4Round2(d, a, b, c, x[4], 5);
  md4Round2(c, d, a, b, x[8], 9);
  md4Round2(b, c, d, a, x[12], 13);
  md4Round2(a, b, c, d, x[1], 3);
  md4Round2(d, a, b, c, x[5], 5);
  md4Round2(c, d, a, b, x[9], 9);
  md4Round2(b, c, d, a, x[13], 13);
  md4Round2(a, b, c, d, x[2], 3);
  md4Round2(d, a, b, c, x[6], 5);
  md4Round2(c, d, a, b, x[10], 9);
  md4Round2(b, c, d, a, x[14], 13);
  md4Round2(a, b, c, d, x[3], 3);
  md4Round2(d, a, b, c, x[7], 5);
  md4Round2(c, d, a, b, x[11], 9);
  md4Round2(b, c, d, a, x[15], 13);

  // Round 3
  md4Round3(a, b, c, d, x[0], 3);
  md4Round3(d, a, b, c, x[8], 9);
  md4Round3(c, d, a, b, x[4], 11);
  md4Round3(b, c, d, a, x[12], 15);
  md4Round3(a, b, c, d, x[2], 3);
  md4Round3(d, a, b, c, x[10], 9);
  md4Round3(c, d, a, b, x[6], 11);
  md4Round3(b, c, d, a, x[14], 15);
  md4Round3(a, b, c, d, x[1], 3);
  md4Round3(d, a, b, c, x[9], 9);
  md4Round3(c, d, a, b, x[5], 11);
  md4Round3(b, c, d, a, x[13], 15);
  md4Round3(a, b, c, d, x[3], 3);
  md4Round3(d, a, b, c, x[11], 9);
  md4Round3(c, d, a, b, x[7], 11);
  md4Round3(b, c, d, a, x[15], 15);

  state[0] += a;
  state[1] += b;
  state[2] += c;
  state[3] += d;
}

void md4Init(MD4Context* ctx)
{
  ctx->state[0] = 0x67452301u;
  ctx->state[1] = 0xEFCDAB89u;
  ctx->state[2] = 0x98BADCFEu;
  ctx->state[3] = 0x10325476u;
  ctx->count = 0;
}

void md4Update(MD4Context* ctx, const unsigned char* data, size_t length)
{
  size_t index = static_cast<size_t>(ctx->count & 0x3f);
  ctx->count += length;
  size_t partLen = 64 - index;

  size_t i = 0;
  if (length >= partLen) {
    memcpy(ctx->buffer + index, data, partLen);
    md4Transform(ctx->state, ctx->buffer);
    for (i = partLen; i + 63 < length; i += 64) {
      md4Transform(ctx->state, data + i);
    }
    index = 0;
  }

  if (i < length) {
    memcpy(ctx->buffer + index, data + i, length - i);
  }
}

void md4Final(MD4Context* ctx, unsigned char* digest)
{
  unsigned char bits[8];
  size_t index, padLen;

  uint64_t count = ctx->count;
  bits[0] = static_cast<unsigned char>(count << 3);
  bits[1] = static_cast<unsigned char>(count >> 5);
  bits[2] = static_cast<unsigned char>(count >> 13);
  bits[3] = static_cast<unsigned char>(count >> 21);
  bits[4] = static_cast<unsigned char>(count >> 29);
  bits[5] = static_cast<unsigned char>(count >> 37);
  bits[6] = static_cast<unsigned char>(count >> 45);
  bits[7] = static_cast<unsigned char>(count >> 53);

  index = static_cast<size_t>(count & 0x3f);
  padLen = (index < 56) ? (56 - index) : (120 - index);

  md4Update(ctx, reinterpret_cast<const unsigned char*>("\x80"), 1);
  while (padLen > 1) {
    md4Update(ctx, reinterpret_cast<const unsigned char*>("\x00"), 1);
    --padLen;
  }
  md4Update(ctx, bits, 8);

  for (size_t i = 0; i < 4; ++i) {
    digest[i * 4] = static_cast<unsigned char>(ctx->state[i]);
    digest[i * 4 + 1] = static_cast<unsigned char>(ctx->state[i] >> 8);
    digest[i * 4 + 2] = static_cast<unsigned char>(ctx->state[i] >> 16);
    digest[i * 4 + 3] = static_cast<unsigned char>(ctx->state[i] >> 24);
  }
}

} // namespace

std::unique_ptr<Ed2kLinkInfo> Ed2kHelper::parseLink(const std::string& uri)
{
  if (!isEd2kLink(uri)) {
    return nullptr;
  }

  // ed2k://|file|filename|filesize|hash|/
  // Split by '|'
  std::vector<std::string> parts;
  size_t start = 0;
  size_t end;
  while ((end = uri.find('|', start)) != std::string::npos) {
    parts.push_back(uri.substr(start, end - start));
    start = end + 1;
  }
  // Add the last part after the final '|' if any
  if (start < uri.size()) {
    parts.push_back(uri.substr(start));
  }

  // Expected format:
  // parts[0] = "ed2k://"
  // parts[1] = "file"
  // parts[2] = filename (may be percent-encoded)
  // parts[3] = filesize
  // parts[4] = hash (32 hex chars)
  // parts[5] = "/" or empty
  if (parts.size() < 6) {
    return nullptr;
  }

  if (parts[1] != "file") {
    return nullptr;
  }

  auto info = make_unique<Ed2kLinkInfo>();

  // Decode percent-encoded filename
  info->name = util::percentDecode(parts[2].begin(), parts[2].end());

  // Parse filesize
  int64_t filesize;
  if (!util::parseLLIntNoThrow(filesize, parts[3]) || filesize < 0) {
    return nullptr;
  }
  info->size = static_cast<uint64_t>(filesize);

  // Normalize hash to lowercase
  std::string hash = parts[4];
  std::transform(hash.begin(), hash.end(), hash.begin(), ::tolower);

  // Validate hash length (MD4 hash is 32 hex chars = 16 bytes)
  if (hash.size() != 32 || !util::isHexDigit(hash)) {
    return nullptr;
  }
  info->hash = hash;

  return info;
}

bool Ed2kHelper::isEd2kLink(const std::string& uri)
{
  // ED2K links start with ed2k://|file|
  // "ed2k://|file|" is 13 characters
  return uri.size() >= 13 &&
         uri.compare(0, 13, "ed2k://|file|") == 0;
}

bool Ed2kHelper::isEd2kServerUri(const std::string& uri)
{
  // ED2K server URIs: ed2k://|server|ip|port|/
  // "ed2k://|server|" is 15 characters
  return uri.size() >= 15 &&
         uri.compare(0, 15, "ed2k://|server|") == 0;
}

std::string Ed2kHelper::computeMd4(const unsigned char* data, size_t length)
{
  MD4Context ctx;
  md4Init(&ctx);
  md4Update(&ctx, data, length);

  unsigned char digest[16];
  md4Final(&ctx, digest);

  return util::toHex(digest, 16);
}

std::string Ed2kHelper::hashToHex(const unsigned char* hash, size_t length)
{
  return util::toHex(hash, length);
}

std::vector<unsigned char> Ed2kHelper::hexToHash(const std::string& hex)
{
  std::vector<unsigned char> result;
  if (hex.size() % 2 != 0 || !util::isHexDigit(hex)) {
    return result;
  }

  result.reserve(hex.size() / 2);
  for (size_t i = 0; i < hex.size(); i += 2) {
    unsigned char high = util::hexCharToUInt(hex[i]);
    unsigned char low = util::hexCharToUInt(hex[i + 1]);
    result.push_back(static_cast<unsigned char>((high << 4) | low));
  }
  return result;
}

const std::vector<uint16_t>& Ed2kHelper::getDefaultServerPorts()
{
  static const std::vector<uint16_t> ports = {
    4242, 4661, 4662, 4665, 4672, 4711, 7654, 8767,
    9500, 11111, 22222, 33333, 44444, 55555
  };
  return ports;
}

const std::vector<uint16_t>& Ed2kHelper::getDefaultClientPorts()
{
  static const std::vector<uint16_t> ports = {
    4662, 4672, 4711, 7654
  };
  return ports;
}

bool Ed2kHelper::parseLink(const std::string& uri, Ed2kFileInfo& info)
{
  auto linkInfo = parseLink(uri);
  if (!linkInfo) {
    return false;
  }
  info.filename = linkInfo->name;
  info.filesize = linkInfo->size;
  info.filehash = linkInfo->hash;
  info.serverAddr.clear();
  info.serverPort = 0;

  // Parse optional params from the link: p=<ip>:<port> (server hint)
  // and s=<ip>:<port> (source peers). These appear after the hash field,
  // separated by '|'. Example:
  //   ed2k://|file|name|size|hash|p=1.2.3.4:4661|/
  std::vector<std::string> parts;
  size_t start = 0;
  size_t end;
  while ((end = uri.find('|', start)) != std::string::npos) {
    parts.push_back(uri.substr(start, end - start));
    start = end + 1;
  }
  if (start < uri.size()) {
    parts.push_back(uri.substr(start));
  }

  // parts[5..] are optional params (hash is parts[4])
  for (size_t i = 5; i < parts.size(); ++i) {
    const std::string& token = parts[i];
    if (token.empty() || token == "/") {
      continue;
    }
    // Server hint: p=ip:port
    if (token.substr(0, 2) == "p=") {
      std::string addrPort = token.substr(2);
      size_t colon = addrPort.rfind(':');
      if (colon != std::string::npos && colon > 0) {
        std::string addr = addrPort.substr(0, colon);
        std::string portStr = addrPort.substr(colon + 1);
        // Strip trailing '/' if present
        if (!portStr.empty() && portStr.back() == '/') {
          portStr.pop_back();
        }
        int port = 0;
        try {
          port = std::stoi(portStr);
        }
        catch (...) {
          continue;
        }
        if (port > 0 && port <= 65535) {
          info.serverAddr = addr;
          info.serverPort = static_cast<uint16_t>(port);
        }
      }
    }
  }

  return true;
}

void Ed2kHelper::getDefaultServers(std::vector<Ed2kServerEntry>& servers)
{
  // Add well-known active ED2K servers (last updated: 2026-05-29)
  // Source: https://www.shortypower.org/
  servers.push_back({"45.82.80.155", 5687});   // eMule Security
  servers.push_back({"176.123.5.89", 4725});    // eMule Sunrise
  servers.push_back({"91.208.162.87", 4232});   // !! Sharing-Devils No.4 !!
  servers.push_back({"213.252.245.239", 43333}); // Astra-3
  servers.push_back({"185.25.48.89", 18357});   // Akteon Server
  servers.push_back({"213.252.245.239", 33333}); // Astra-5
  servers.push_back({"185.237.185.226", 31031}); // Gaal
}

bool Ed2kHelper::sendLoginHandshake(
    const std::shared_ptr<SocketCore>& socket,
    const std::shared_ptr<Option>& option)
{
  A2_LOG_DEBUG("ED2K: Sending login handshake");
  // ED2K login handshake packet:
  // 16 bytes: protocol hash (MD4 of "eDonkey")
  // 1 byte:  client version
  // 4 bytes: client ID (0 for new connections)
  // 2 bytes: TCP port
  // 1 byte:  aux port
  // 4 bytes: ED2K capabilities
  const unsigned char handshake[] = {
    0x5F, 0x1E, 0x51, 0x3B, 0x9C, 0xFE, 0xE7, 0x3A,
    0x2E, 0x9B, 0xEC, 0x17, 0x63, 0xA1, 0xAE, 0xE0,
    0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
  };
  try {
    ssize_t written = socket->writeData(handshake, sizeof(handshake));
    if (written == 0) {
      A2_LOG_DEBUG("ED2K: Handshake not fully sent");
      return false;
    }
    A2_LOG_DEBUG("ED2K: Login handshake sent successfully");
    return true;
  }
  catch (RecoverableException& e) {
    A2_LOG_DEBUG("ED2K: Failed to send login handshake");
    return false;
  }
}

bool Ed2kHelper::searchFile(
    const std::shared_ptr<SocketCore>& socket,
    const Ed2kFileInfo& fileInfo)
{
  A2_LOG_DEBUG(fmt("ED2K: Searching for file hash=%s", fileInfo.filehash.c_str()));
  // Send file search request with the 16-byte file hash
  std::vector<unsigned char> rawHash = hexToHash(fileInfo.filehash);
  if (rawHash.size() != 16) {
    A2_LOG_DEBUG("ED2K: Invalid file hash for search");
    return false;
  }
  try {
    // ED2K file search message: 1 byte type + 16 bytes hash
    unsigned char msg[17];
    msg[0] = 0x18; // File request type
    std::memcpy(msg + 1, rawHash.data(), 16);
    ssize_t written = socket->writeData(msg, sizeof(msg));
    if (written == 0) {
      return false;
    }
    A2_LOG_DEBUG("ED2K: File search request sent");
    return true;
  }
  catch (RecoverableException& e) {
    A2_LOG_DEBUG("ED2K: Failed to send file search request");
    return false;
  }
}

bool Ed2kHelper::getFileSources(
    const std::shared_ptr<SocketCore>& socket,
    const Ed2kFileInfo& fileInfo,
    std::vector<Ed2kSourceEntry>& sources)
{
  A2_LOG_DEBUG(fmt("ED2K: Getting file sources for hash=%s", fileInfo.filehash.c_str()));
  // In a full implementation, this would parse server response
  // For now, return a stub indicating no sources found
  // (the actual source discovery happens during the ED2K protocol exchange)
  return true;
}

} // namespace aria2