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
#ifndef D_NAT_PMP_CONTEXT_H
#define D_NAT_PMP_CONTEXT_H

#include "common.h"

#include <cstddef>

namespace aria2 {

// Minimal NAT-PMP (RFC 6886) client used for NAT traversal.
//
// NAT-PMP is the UPnP alternative supported by Apple AirPort base
// stations and many older routers. It is a tiny request/response
// protocol over UDP port 5351 on the gateway's all-hosts multicast
// address (224.0.0.1). No XML, no HTTP — a handful of fixed-layout
// packets. The gateway answers with the port mapping result.
//
// Same lifecycle as UPnPContext: best-effort, hard short timeouts,
// runs once per process (on the first BitTorrent download, after the
// UPnP attempt when that failed to map), removed on engine shutdown.
// Mappings are requested with a 24h lifetime; the engine typically
// does not run longer than that without a restart, which renews it.
class NatPmpContext {
public:
  NatPmpContext();

  // Map external TCP port == internal TCP port. Returns true if the
  // gateway confirmed the mapping.
  bool addPortMapping(uint16_t port);

  // Best-effort removal of the mapping created by addPortMapping().
  void removePortMapping();

  // True if the network sequence already ran in this process.
  static bool alreadyAttempted();

  // Whether a mapping is currently in place.
  bool isMapped() const { return mapped_; }

private:
  // One request/response exchange over UDP 224.0.0.1:5351. Returns
  // false on timeout/error. respLen is set to the received length.
  bool exchange(const unsigned char* req, size_t reqLen,
                unsigned char* resp, size_t respCap, size_t& respLen);

  uint16_t mappedPort_ = 0;
  bool mapped_ = false;
  bool attempted_ = false;
  static bool attemptedAny_;
};

// Process-wide singleton used by BtSetup (mapping) and DownloadEngine
// shutdown (cleanup).
NatPmpContext& getNatPmpContext();

} // namespace aria2

#endif // D_NAT_PMP_CONTEXT_H
