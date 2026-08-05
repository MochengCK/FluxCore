/* <!-- copyright */
/*
 * aria2 - The high speed download utility
 *
 * Copyright (C) 2026 The XferCore Authors
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
#include "UtpPacket.h"

#include <cstring>

namespace aria2 {
namespace utp {

namespace {

uint16_t readBe16(const unsigned char* p)
{
  return static_cast<uint16_t>((static_cast<uint16_t>(p[0]) << 8) | p[1]);
}

uint32_t readBe32(const unsigned char* p)
{
  return (static_cast<uint32_t>(p[0]) << 24) |
         (static_cast<uint32_t>(p[1]) << 16) |
         (static_cast<uint32_t>(p[2]) << 8) | static_cast<uint32_t>(p[3]);
}

void writeBe16(unsigned char* p, uint16_t v)
{
  p[0] = static_cast<unsigned char>(v >> 8);
  p[1] = static_cast<unsigned char>(v & 0xFF);
}

void writeBe32(unsigned char* p, uint32_t v)
{
  p[0] = static_cast<unsigned char>(v >> 24);
  p[1] = static_cast<unsigned char>(v >> 16);
  p[2] = static_cast<unsigned char>(v >> 8);
  p[3] = static_cast<unsigned char>(v & 0xFF);
}

} // namespace

bool parsePacket(const unsigned char* data, size_t len, PacketHeader& header,
                 std::vector<std::pair<uint8_t, std::vector<uint8_t>>>&
                     extensions)
{
  extensions.clear();
  if (len < HEADER_LEN) {
    return false;
  }
  // BEP 29: first byte is (type << 4) | version.
  header.type = (data[0] >> 4) & 0x0F;
  header.version = data[0] & 0x0F;
  if (header.version != PROTOCOL_VERSION) {
    return false;
  }
  header.extension = data[1];
  header.connectionId = readBe16(data + 2);
  header.timestamp = readBe32(data + 4);
  header.timestampDiff = readBe32(data + 8);
  header.wndSize = readBe32(data + 12);
  header.seqNr = readBe16(data + 16);
  header.ackNr = readBe16(data + 18);

  // Walk the extension chain: each extension is [type][len][payload].
  size_t off = HEADER_LEN;
  uint8_t extType = header.extension;
  while (extType != EXT_NONE) {
    if (off + 2 > len) {
      return false;
    }
    uint8_t nextType = data[off];
    uint8_t extLen = data[off + 1];
    off += 2;
    if (off + extLen > len) {
      return false;
    }
    extensions.emplace_back(
        extType, std::vector<unsigned char>(data + off, data + off + extLen));
    off += extLen;
    extType = nextType;
  }
  return true;
}

void encodeHeader(unsigned char* out, const PacketHeader& header)
{
  std::memset(out, 0, HEADER_LEN);
  out[0] = static_cast<unsigned char>(((header.type & 0x0F) << 4) |
                                      (header.version & 0x0F));
  out[1] = header.extension;
  writeBe16(out + 2, header.connectionId);
  writeBe32(out + 4, header.timestamp);
  writeBe32(out + 8, header.timestampDiff);
  writeBe32(out + 12, header.wndSize);
  writeBe16(out + 16, header.seqNr);
  writeBe16(out + 18, header.ackNr);
}

void appendSackExtension(unsigned char* out, size_t& off, uint32_t sackBits)
{
  // [type=1][len=4][4-byte bitmap]. Per BEP 29 the bitmap byte order is
  // reversed relative to big-endian: the first wire byte carries bits
  // ack_nr+2..ack_nr+9 with the LSB = ack_nr+2 — i.e. the bitmap is
  // stored little-endian.
  out[off] = EXT_NONE;
  out[off + 1] = 4;
  for (size_t i = 0; i < 4; ++i) {
    out[off + 2 + i] = static_cast<unsigned char>((sackBits >> (8 * i)) & 0xFF);
  }
  off += 2 + 4;
}

uint32_t decodeSackBits(const unsigned char* payload, size_t len)
{
  uint32_t bits = 0;
  if (len < 4) {
    return 0;
  }
  for (size_t i = 0; i < 4; ++i) {
    bits |= static_cast<uint32_t>(payload[i]) << (8 * i);
  }
  return bits;
}

} // namespace utp
} // namespace aria2
