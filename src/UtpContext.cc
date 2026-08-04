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
#include "UtpContext.h"

#include <chrono>

#include "SocketCore.h"
#include "UtpConnection.h"
#include "a2functional.h"
#include "UtpPacket.h"
#include "LogFactory.h"
#include "Logger.h"
#include "fmt.h"
#include "RecoverableException.h"

namespace aria2 {
namespace utp {

namespace {
constexpr size_t MAX_DATAGRAM = 2048;
}

UtpContext::UtpContext() = default;

UtpContext::~UtpContext() = default;

uint32_t UtpContext::nowUs()
{
  using namespace std::chrono;
  auto now = steady_clock::now().time_since_epoch();
  return static_cast<uint32_t>(
      duration_cast<microseconds>(now).count() & 0xFFFFFFFF);
}

bool UtpContext::start()
{
  try {
    socket_ = std::make_shared<SocketCore>(SOCK_DGRAM);
    socket_->bindWithFamily(0, AF_INET);
    socket_->setNonBlockingMode();
    started_ = true;
    A2_LOG_INFO(fmt("uTP: UDP socket bound on port %u",
                    static_cast<unsigned>(socket_->getAddrInfo().port)));
    return true;
  }
  catch (RecoverableException& e) {
    A2_LOG_WARN(fmt("uTP: failed to bind UDP socket: %s", e.what()));
    socket_.reset();
    return false;
  }
}

std::shared_ptr<UtpConnection> UtpContext::connect(const std::string& addr, uint16_t port)
{
  if (!started_) {
    return nullptr;
  }
  auto conn = std::make_shared<UtpConnection>(addr, port, nowUs());
  connections_.emplace(conn->getRecvId(), conn);
  return conn;
}

void UtpContext::processTick()
{
  if (!started_) {
    return;
  }
  uint32_t now = nowUs();

  // 1. Advance every connection (timers, retransmit, CC-gated flush).
  for (auto& kv : connections_) {
    kv.second->processTick(now);
  }

  // 2. Remove dead connections.
  for (auto it = connections_.begin(); it != connections_.end();) {
    auto& conn = it->second;
    if (conn->isClosed() || conn->hasError()) {
      it = connections_.erase(it);
    }
    else {
      ++it;
    }
  }

  // 3. Flush outboxes over the shared UDP socket.
  for (auto& kv : connections_) {
    auto& conn = kv.second;
    std::vector<std::vector<unsigned char>> out;
    conn->drainOutbox(out);
    for (auto& pkt : out) {
      sendDatagram(pkt.data(), pkt.size(), conn->getRemoteAddr(),
                   conn->getRemotePort());
    }
  }
}

void UtpContext::receiveLoop()
{
  if (!started_ || !socket_) {
    return;
  }
  unsigned char buf[MAX_DATAGRAM];
  while (true) {
    Endpoint sender;
    ssize_t n = 0;
    try {
      n = socket_->readDataFrom(buf, sizeof(buf), sender);
    }
    catch (RecoverableException&) {
      break;
    }
    if (n <= 0) {
      break; // EAGAIN or no more data
    }

    PacketHeader hdr;
    std::vector<std::pair<uint8_t, std::vector<uint8_t>>> exts;
    if (!parsePacket(buf, static_cast<size_t>(n), hdr, exts)) {
      continue;
    }

    UtpConnection* conn = find(hdr.connectionId);
    if (conn) {
      conn->handlePacket(buf, static_cast<size_t>(n), nowUs());
      continue;
    }

    // Unknown connection id. A SYN starts a new inbound connection.
    if (hdr.type == ST_SYN) {
      auto incoming = std::make_shared<UtpConnection>(
          sender.addr, sender.port, hdr.connectionId, hdr.seqNr, nowUs());
      connections_.emplace(incoming->getRecvId(), incoming);
      A2_LOG_INFO(fmt("uTP: accepted inbound SYN from %s:%u (recvId=%u)",
                      sender.addr.c_str(), sender.port,
                      static_cast<unsigned>(incoming->getRecvId())));
      if (acceptHandler_) {
        acceptHandler_(incoming);
      }
    }
    // else: datagram for a connection we already closed — drop (a
    // production impl would answer RESET; the peer times out instead).
  }
}

UtpConnection* UtpContext::find(uint16_t recvId)
{
  auto it = connections_.find(recvId);
  return it == connections_.end() ? nullptr : it->second.get();
}

void UtpContext::removeConnection(UtpConnection* conn)
{
  if (!conn) {
    return;
  }
  connections_.erase(conn->getRecvId());
}

void UtpContext::sendDatagram(const unsigned char* data, size_t len,
                              const std::string& addr, uint16_t port)
{
  if (!socket_) {
    return;
  }
  try {
    socket_->writeData(data, len, addr, port);
  }
  catch (RecoverableException& e) {
    A2_LOG_DEBUG(fmt("uTP: send to %s:%u failed: %s", addr.c_str(), port,
                     e.what()));
  }
}

} // namespace utp
} // namespace aria2
