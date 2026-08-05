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
#ifndef D_UTP_CONTEXT_H
#define D_UTP_CONTEXT_H

#include "common.h"

#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <string>
#include <vector>

namespace aria2 {

class SocketCore;

namespace utp {

class UtpConnection;

// Host for all uTP connections: owns the shared UDP socket, routes
// incoming datagrams to connections by receive id, and drives every
// connection's timers/congestion control once per engine tick.
//
// Driven by the engine's UtpCommand (see UtpCommand.h): each engine
// iteration calls processTick() (advance timers, flush CC-gated data,
// retransmits) and receiveLoop() (drain the UDP socket). Outgoing
// datagrams produced by connections are sent inside processTick().
class UtpContext {
public:
  // Called for each newly accepted inbound connection (after the SYN).
  // The engine installs a handler that spawns a peer interaction
  // command over the uTP transport. The shared_ptr keeps the connection
  // alive for the transport even after it leaves the registry.
  using AcceptHandler =
      std::function<void(const std::shared_ptr<UtpConnection>&)>;

  UtpContext();
  ~UtpContext();

  // Bind the UDP socket. port==0 uses an ephemeral port. Standard BT
  // convention: uTP MUST listen on the same port as the TCP BT listener
  // — remote peers send uTP SYNs to our advertised listen port. Calling
  // with the real TCP port (from BtSetup) fixes inbound uTP; a port
  // conflict falls back to an ephemeral port so outbound uTP still
  // works. Idempotent: returns true if already started.
  bool start(uint16_t port = 0);

  // True once the UDP socket is bound.
  bool isStarted() const { return started_; }

  // Create an outbound connection to addr:port (already in SYN_SENT
  // with the SYN queued). nullptr if not started.
  std::shared_ptr<UtpConnection> connect(const std::string& addr,
                                         uint16_t port);

  // Drive all connections: timers, retransmission, CC-gated data flush,
  // and send all queued datagrams.
  void processTick();

  // Drain all pending UDP datagrams and dispatch them.
  void receiveLoop();

  void setAcceptHandler(AcceptHandler handler) { acceptHandler_ = handler; }

  size_t countConnections() const { return connections_.size(); }

  // Monotonic µs clock used by all connections.
  static uint32_t nowUs();

  // The underlying UDP socket (for engine read-check registration).
  std::shared_ptr<SocketCore> getSocket() const { return socket_; }

  // Drop a finished/failed connection.
  void removeConnection(UtpConnection* conn);

private:
  UtpConnection* find(uint16_t recvId);
  void sendDatagram(const unsigned char* data, size_t len,
                    const std::string& addr, uint16_t port);

  std::shared_ptr<SocketCore> socket_;
  std::map<uint16_t, std::shared_ptr<UtpConnection>> connections_;
  AcceptHandler acceptHandler_;
  bool started_ = false;
};

} // namespace utp
} // namespace aria2

#endif // D_UTP_CONTEXT_H
