/* <!-- copyright */
/*
 * aria2 - The high speed download utility
 *
 * Copyright (C) 2006 Tatsuhiro Tsujikawa
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
#include "ProtocolDetector.h"

#include <cstring>
#include <iomanip>
#include <cctype>

#include "Request.h"
#include "File.h"
#include "util.h"
#include "RecoverableException.h"
#include "uri.h"
#include "BufferedFile.h"
#ifdef ENABLE_BITTORRENT
#  include "bittorrent_helper.h"
#endif // ENABLE_BITTORRENT

namespace aria2 {

namespace {
bool looksLikeWindowsDrivePath(const std::string& uri)
{
  return uri.size() >= 3 &&
         std::isalpha(static_cast<unsigned char>(uri[0])) &&
         uri[1] == ':' && (uri[2] == '/' || uri[2] == '\\');
}

std::string normalizeWindowsDrivePath(const std::string& uri)
{
  if (!looksLikeWindowsDrivePath(uri)) {
    return uri;
  }

  std::string path;
  path.push_back(uri[0]);
  path.push_back(':');

  size_t i = 2;
  while (i < uri.size() && (uri[i] == '/' || uri[i] == '\\')) {
    ++i;
  }

  path.push_back('/');
  path.append(uri.begin() + i, uri.end());
  return path;
}
} // namespace

ProtocolDetector::ProtocolDetector() = default;

ProtocolDetector::~ProtocolDetector() = default;

bool ProtocolDetector::isStreamProtocol(const std::string& uri) const
{
  if (looksLikeWindowsDrivePath(uri)) {
    if (File(uri).exists()) {
      return false;
    }

    const auto normalized = normalizeWindowsDrivePath(uri);
    if (normalized != uri && File(normalized).exists()) {
      return false;
    }
  }

  return uri_split(nullptr, uri.c_str()) == 0;
}

bool ProtocolDetector::guessTorrentFile(const std::string& uri) const
{
  auto checkHead = [](const std::string& path) {
    BufferedFile fp(path.c_str(), BufferedFile::READ);
    if (!fp) {
      return -1;
    }
    char head[1];
    if (fp.read(head, sizeof(head)) == sizeof(head)) {
      return head[0] == 'd' ? 1 : 0;
    }
    return 0;
  };

  int r = checkHead(uri);
  if (r != -1) {
    return r == 1;
  }

  if (looksLikeWindowsDrivePath(uri)) {
    const auto normalized = normalizeWindowsDrivePath(uri);
    if (normalized != uri) {
      r = checkHead(normalized);
      if (r != -1) {
        return r == 1;
      }
    }
  }

  return false;
}

bool ProtocolDetector::guessTorrentMagnet(const std::string& uri) const
{
#ifdef ENABLE_BITTORRENT
  try {
    bittorrent::parseMagnet(uri);
    return true;
  }
  catch (RecoverableException& e) {
    return false;
  }
#else  // !ENABLE_BITTORRENT
  return false;
#endif // !ENABLE_BITTORRENT
}

bool ProtocolDetector::guessMetalinkFile(const std::string& uri) const
{
  auto checkHead = [](const std::string& path) {
    BufferedFile fp(path.c_str(), BufferedFile::READ);
    if (!fp) {
      return -1;
    }
    char head[5];
    if (fp.read(head, sizeof(head)) == sizeof(head)) {
      return memcmp(head, "<?xml", 5) == 0 ? 1 : 0;
    }
    return 0;
  };

  int r = checkHead(uri);
  if (r != -1) {
    return r == 1;
  }

  if (looksLikeWindowsDrivePath(uri)) {
    const auto normalized = normalizeWindowsDrivePath(uri);
    if (normalized != uri) {
      r = checkHead(normalized);
      if (r != -1) {
        return r == 1;
      }
    }
  }

  return false;
}

} // namespace aria2
