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
#include "NatPmpContext.h"

#include <cstring>

#include "SocketCore.h"
#include "LogFactory.h"
#include "Logger.h"
#include "fmt.h"
#include "RecoverableException.h"

namespace aria2 {

namespace {

// NAT-PMP well-known gateway multicast address and port.
constexpr char PMP_GATEWAY_ADDR[] = "224.0.0.1";
constexpr uint16_t PMP_PORT = 5351;

constexpr time_t PMP_WAIT_SECONDS = 2;

// NAT-PMP opcodes.
constexpr unsigned char OP_MAP_TCP = 2;
// Result code in replies: high bit set means success.
constexpr unsigned char REPLY_SUCCESS = 0x80;
// Requested mapping lifetime in seconds (24h; gateways may clamp).
constexpr uint32_t MAPPING_LIFETIME = 24 * 60 * 60;

inline void appendBe16(unsigned char* p, uint16_t v)
{
  p[0] = static_cast<unsigned char>(v >> 8);
  p[1] = static_cast<unsigned char>(v & 0xFF);
}

} // namespace

bool NatPmpContext::attemptedAny_ = false;

NatPmpContext::NatPmpContext() = default;

NatPmpContext& getNatPmpContext()
{
  static NatPmpContext ctx;
  return ctx;
}

bool NatPmpContext::alreadyAttempted() { return attemptedAny_; }

bool NatPmpContext::exchange(const unsigned char* req, size_t reqLen,
                             unsigned char* resp, size_t respCap,
                             size_t& respLen)
{
  std::shared_ptr<SocketCore> udp;
  try {
    udp = std::make_shared<SocketCore>(SOCK_DGRAM);
    udp->bindWithFamily(0, AF_INET);
    udp->setMulticastTtl(2);
  }
  catch (RecoverableException& e) {
    A2_LOG_DEBUG(fmt("NAT-PMP: socket init failed: %s", e.what()));
    return false;
  }

  try {
    udp->writeData(req, reqLen, PMP_GATEWAY_ADDR, PMP_PORT);
  }
  catch (RecoverableException& e) {
    A2_LOG_DEBUG(fmt("NAT-PMP: request send failed: %s", e.what()));
    return false;
  }

  if (!udp->isReadable(PMP_WAIT_SECONDS)) {
    return false;
  }
  Endpoint sender;
  ssize_t n = 0;
  try {
    n = udp->readDataFrom(resp, respCap, sender);
  }
  catch (RecoverableException&) {
    return false;
  }
  if (n <= 0) {
    return false;
  }
  respLen = static_cast<size_t>(n);
  return true;
}

bool NatPmpContext::addPortMapping(uint16_t port)
{
  if (attemptedAny_) {
    return mapped_;
  }
  attemptedAny_ = true;
  attempted_ = true;

  if (port == 0) {
    A2_LOG_WARN("NAT-PMP: no valid port to map, skipping");
    return false;
  }

  // Map request (RFC 6886 §3.3):
  //   [ver=0][op=2 (TCP)][2B reserved][2B internal port]
  //   [2B external port][4B lifetime]
  unsigned char req[12] = {0, OP_MAP_TCP};
  appendBe16(req + 2, 0);       // reserved
  appendBe16(req + 4, port);    // internal port
  appendBe16(req + 6, port);    // requested external port
  req[8] = static_cast<unsigned char>(MAPPING_LIFETIME >> 24);
  req[9] = static_cast<unsigned char>(MAPPING_LIFETIME >> 16);
  req[10] = static_cast<unsigned char>(MAPPING_LIFETIME >> 8);
  req[11] = static_cast<unsigned char>(MAPPING_LIFETIME & 0xFF);

  unsigned char resp[16];
  size_t respLen = 0;
  if (!exchange(req, sizeof(req), resp, sizeof(resp), respLen)) {
    A2_LOG_INFO("NAT-PMP: no gateway response (NAT traversal via "
                "NAT-PMP unavailable)");
    return false;
  }

  // Reply (RFC 6886 §3.4): [ver=0][op=0x80|2][4B epoch]
  //   [2B internal port][2B external port][4B lifetime]
  if (respLen < 12 || resp[0] != 0 || (resp[1] & 0x7F) != OP_MAP_TCP) {
    A2_LOG_WARN("NAT-PMP: malformed gateway reply");
    return false;
  }
  if (!(resp[1] & REPLY_SUCCESS)) {
    A2_LOG_WARN(fmt("NAT-PMP: gateway rejected mapping with code %u",
                    static_cast<unsigned>(resp[1])));
    return false;
  }

  mapped_ = true;
  mappedPort_ = port;
  A2_LOG_INFO(fmt("NAT-PMP: TCP port %u mapped on gateway (NAT traversal "
                  "active, 24h lease)",
                  static_cast<unsigned>(port)));
  return true;
}

void NatPmpContext::removePortMapping()
{
  if (!mapped_ || mappedPort_ == 0) {
    return;
  }
  // Delete = map request with lifetime 0.
  unsigned char req[12] = {0, OP_MAP_TCP};
  appendBe16(req + 2, 0);
  appendBe16(req + 4, mappedPort_);
  appendBe16(req + 6, mappedPort_);
  // lifetime stays zero → delete
  unsigned char resp[16];
  size_t respLen = 0;
  if (exchange(req, sizeof(req), resp, sizeof(resp), respLen)) {
    A2_LOG_INFO("NAT-PMP: port mapping removed on engine shutdown");
  }
  mapped_ = false;
}

} // namespace aria2
