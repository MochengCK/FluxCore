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
#ifndef D_DHT_FIREWALL_STATE_H
#define D_DHT_FIREWALL_STATE_H

#include "common.h"
#include "TimerA2.h"

#include <set>
#include <string>

namespace aria2 {

// Detects whether this node's UDP port is reachable from the outside
// (BEP 5 firewall check, simplified).
//
// A NAT without a port mapping only forwards UDP packets that arrive
// from an IP/port we recently sent a packet to (the NAT mapping). So if
// we receive an inbound DHT *query* from an IP we have never contacted,
// the packet could only have arrived through an open port — we are NOT
// firewalled. Queries from IPs we did contact prove nothing, since the
// NAT mapping covers them.
//
// announce_peer messages are gated on canAnnounce(): firewalled nodes
// keep looking peers up (get_peers still works) but stop announcing
// themselves after a short optimistic grace window, which keeps the
// network free of unreachable announces.
class DHTFirewallState {
public:
  DHTFirewallState();

  // Record that we sent a message to this IP.
  void noteOutbound(const std::string& ip);
  // Record an inbound query (request, not reply) from this IP.
  void noteInboundQuery(const std::string& ip);

  // True once inbound reachability has been proven.
  bool isOpen() const { return open_; }

  // announce_peer is allowed while the port is proven open, or during
  // the initial grace window before the check has had time to conclude.
  bool canAnnounce() const;

private:
  // IPs we have sent messages to (bounded to avoid unbounded growth).
  std::set<std::string> contactedIps_;
  bool open_ = false;
  Timer startTime_;
  static constexpr size_t MAX_CONTACTED_IPS = 512;
  // How long to keep announcing before requiring proof of openness.
  static constexpr int GRACE_SECONDS = 90;
};

} // namespace aria2

#endif // D_DHT_FIREWALL_STATE_H
