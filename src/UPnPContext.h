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
#ifndef D_UPNP_CONTEXT_H
#define D_UPNP_CONTEXT_H

#include "common.h"

#include <string>

namespace aria2 {

// Minimal, dependency-free UPnP IGD client used for NAT traversal.
//
// Most consumer routers implement UPnP-IGD v1: a UDP SSDP discovery
// finds the gateway's device-description URL, an HTTP GET fetches the
// description XML which points at the WANIPConnection/WANPPPConnection
// service, and a SOAP POST (AddPortMapping) opens a TCP port on the
// external interface, forwarding to this host. This makes the
// BitTorrent client reachable from the outside world, dramatically
// improving swarm participation behind NAT.
//
// Design notes:
//  - No external dependencies: plain sockets (SocketCore) + string
//    parsing. The XML scan is deliberately naive (first serviceType
//    match, next controlURL) — IGD descriptions are simple flat
//    documents and this keeps the parser small and auditable.
//  - Everything is best-effort: every step is wrapped in try/catch,
//    all failures are logged as warnings and never fatal. If no IGD
//    exists the discovery simply times out (~1.5s) and we move on.
//  - Blocking with short timeouts; intended to run exactly once per
//    process, on the first BitTorrent download, while the engine is
//    still starting. Total worst-case stall is a few seconds.
//  - Mappings are permanent (lease 0) and removed on engine shutdown
//    via removePortMapping().
class UPnPContext {
public:
  UPnPContext();

  // Run the full sequence (discovery + AddPortMapping) for the given
  // TCP port (external == internal == port). Returns true if a mapping
  // was successfully created. Safe to call multiple times: only the
  // first call performs network work; later calls return the cached
  // result.
  bool addPortMapping(uint16_t port);

  // Best-effort removal of the mapping created by addPortMapping().
  void removePortMapping();

  // True if the network sequence already ran in this process.
  static bool alreadyAttempted();

  // Whether a mapping is currently in place.
  bool isMapped() const { return mapped_; }

private:
  // Step 1: SSDP M-SEARCH, returns the first LOCATION URL of an IGD.
  bool ssdpDiscover(std::string& location);
  // Step 2: fetch device description XML, fill controlUrl_/serviceType_.
  bool fetchControlUrl(const std::string& location);
  // Step 3: send a SOAP action to the IGD control URL.
  bool soapAction(const std::string& actionName, const std::string& body,
                  const std::string& host, uint16_t port,
                  const std::string& path);

  std::string controlUrl_;
  std::string serviceType_;
  uint16_t mappedPort_ = 0;
  bool mapped_ = false;
  bool attempted_ = false;
  static bool attemptedAny_;
};

} // namespace aria2

namespace aria2 {
// Process-wide UPnPContext singleton used by BtSetup (mapping) and
// DownloadEngine shutdown (cleanup).
UPnPContext& getUPnPContext();
} // namespace aria2

#endif // D_UPNP_CONTEXT_H
