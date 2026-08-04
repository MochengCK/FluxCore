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
#include "UtpSocketLike.h"

#include <cstring>

#include "UtpConnection.h"

namespace aria2 {

ssize_t UtpSocketLike::writeData(const void* data, size_t len)
{
  if (!conn_) {
    return -1;
  }
  size_t accepted = conn_->write(static_cast<const unsigned char*>(data), len);
  return static_cast<ssize_t>(accepted);
}

ssize_t UtpSocketLike::writeVector(a2iovec* iov, size_t iovcnt)
{
  if (!conn_) {
    return -1;
  }
  // uTP sends contiguous packets; coalesce the (few, small) iovs into
  // one buffer instead of scattering.
  size_t total = 0;
  for (size_t i = 0; i < iovcnt; ++i) {
    total += iov[i].iov_len;
  }
  if (total == 0) {
    return 0;
  }
  std::vector<unsigned char> buf(total);
  size_t off = 0;
  for (size_t i = 0; i < iovcnt; ++i) {
    std::memcpy(buf.data() + off, iov[i].iov_base, iov[i].iov_len);
    off += iov[i].iov_len;
  }
  size_t accepted = conn_->write(buf.data(), buf.size());
  return static_cast<ssize_t>(accepted);
}

void UtpSocketLike::readData(void* data, size_t& len)
{
  if (!conn_) {
    len = 0;
    return;
  }
  size_t n = conn_->read(static_cast<unsigned char*>(data), len);
  len = n;
}

bool UtpSocketLike::wantRead() const
{
  return conn_ && conn_->wantRead();
}

bool UtpSocketLike::wantWrite() const
{
  return conn_ && conn_->wantWrite();
}

bool UtpSocketLike::isOpen() const
{
  return conn_ && !conn_->isClosed() && !conn_->hasError();
}

void UtpSocketLike::closeConnection()
{
  if (conn_) {
    conn_->close();
  }
}

} // namespace aria2
