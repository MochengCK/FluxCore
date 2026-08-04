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
#ifndef D_UTP_SOCKET_LIKE_H
#define D_UTP_SOCKET_LIKE_H

#include "SocketLike.h"

#include <memory>
#include <vector>

namespace aria2 {
namespace utp {
class UtpConnection;
} // namespace utp

// SocketLike adapter over a uTP connection. The connection is owned via
// shared_ptr so the transport stays valid even after UtpContext removes
// the connection from its registry (closed/errored) while a peer
// command still holds the transport.
//
// readData/writeData map to the uTP stream API; wantRead/wantWrite
// reflect the connection's current deliverability / CC-gated send state
// (data is actually pumped by utp::UtpCommand's processTick).
class UtpSocketLike : public SocketLike {
public:
  explicit UtpSocketLike(const std::shared_ptr<utp::UtpConnection>& conn)
      : conn_(conn)
  {
  }

  virtual ssize_t writeData(const void* data, size_t len) CXX11_OVERRIDE;
  virtual ssize_t writeVector(a2iovec* iov, size_t iovcnt) CXX11_OVERRIDE;
  virtual void readData(void* data, size_t& len) CXX11_OVERRIDE;
  virtual bool wantRead() const CXX11_OVERRIDE;
  virtual bool wantWrite() const CXX11_OVERRIDE;
  virtual bool isOpen() const CXX11_OVERRIDE;
  virtual void closeConnection() CXX11_OVERRIDE;

  const std::shared_ptr<utp::UtpConnection>& getConnection() const
  {
    return conn_;
  }

private:
  std::shared_ptr<utp::UtpConnection> conn_;
};

} // namespace aria2

#endif // D_UTP_SOCKET_LIKE_H
