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
#ifndef D_UTP_PACKET_H
#define D_UTP_PACKET_H

#include "common.h"

#include <cstdint>
#include <vector>

namespace aria2 {
namespace utp {

// uTP protocol constants and packet (de)serialization, per BEP 29.
//
// The fixed header is 20 bytes, BIG-endian (network order):
//   bit 4-7   type       0=ST_DATA 1=ST_FIN 2=ST_STATE 3=ST_RESET 4=ST_SYN
//   bit 0-3   version    =1
//   byte 1    extension  first extension type (0 = none)
//   bytes 2-3 connection_id  (sender's receive id; SYN carries it too)
//   bytes 4-7 timestamp_microseconds
//   bytes 8-11 timestamp_difference_microseconds (one-way delay echo)
//   bytes 12-15 wnd_size (advertised receive window, bytes)
//   bytes 16-17 seq_nr (packet sequence number)
//   bytes 18-19 ack_nr (last contiguous received sequence number)

constexpr uint8_t ST_DATA = 0;
constexpr uint8_t ST_FIN = 1;
constexpr uint8_t ST_STATE = 2;
constexpr uint8_t ST_RESET = 3;
constexpr uint8_t ST_SYN = 4;

constexpr uint8_t PROTOCOL_VERSION = 1;
constexpr size_t HEADER_LEN = 20;

constexpr uint8_t EXT_NONE = 0;
constexpr uint8_t EXT_SACK = 1;
constexpr uint8_t EXT_TIMESTAMP = 2; // not used; documented for completeness

struct PacketHeader {
  uint8_t type = 0;
  uint8_t version = PROTOCOL_VERSION;
  uint8_t extension = EXT_NONE;
  uint16_t connectionId = 0;
  uint32_t timestamp = 0;       // µs, sender clock
  uint32_t timestampDiff = 0;   // µs, one-way delay echo
  uint32_t wndSize = 0;         // bytes, advertised receive window
  uint16_t seqNr = 0;
  uint16_t ackNr = 0;
};

// Parse a packet header + extension list from a received datagram.
// Returns false if the datagram is too short or has an unsupported
// version. On success header is filled and extensions contains
// (type, payload) pairs in wire order.
bool parsePacket(const unsigned char* data, size_t len, PacketHeader& header,
                 std::vector<std::pair<uint8_t, std::vector<uint8_t>>>&
                     extensions);

// Encode the header into the first HEADER_LEN bytes of a packet buffer.
void encodeHeader(unsigned char* out, const PacketHeader& header);

// Encode a Selective ACK extension: covers seq numbers ack_nr+2 ..
// ack_nr+33, bit i set means acked. The 4-byte bitmap is stored in
// REVERSED byte order per BEP 29: byte0 LSB == ack_nr+2 ... byte3 MSB
// == ack_nr+33.
void appendSackExtension(unsigned char* out, size_t& off, uint32_t sackBits);

// Decode the SACK bitmap from an extension payload (>= 4 bytes).
uint32_t decodeSackBits(const unsigned char* payload, size_t len);

} // namespace utp
} // namespace aria2

#endif // D_UTP_PACKET_H
