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
#ifndef D_MULTI_MIRROR_URI_SELECTOR_H
#define D_MULTI_MIRROR_URI_SELECTOR_H
#include "common.h"
#include "URISelector.h"

#include <memory>
#include <map>
#include <set>
#include <cstdint>

namespace aria2 {

typedef int64_t cuid_t;

class ServerStatMan;
class RequestGroup;

class MultiMirrorURISelector : public URISelector {
private:
  std::shared_ptr<ServerStatMan> serverStatMan_;
  RequestGroup* requestGroup_;
  
  // Track which URI is assigned to which connection (cuid)
  std::map<std::string, std::set<cuid_t>> uriToCuids_;
  
  // Track which cuid is using which URI
  std::map<cuid_t, std::string> cuidToUri_;

  std::string selectBestAvailableUri(
      FileEntry* fileEntry,
      const std::vector<std::pair<size_t, std::string>>& usedHosts);

public:
  MultiMirrorURISelector(std::shared_ptr<ServerStatMan> serverStatMan,
                         RequestGroup* requestGroup);

  virtual ~MultiMirrorURISelector();

  virtual std::string
  select(FileEntry* fileEntry,
         const std::vector<std::pair<size_t, std::string>>& usedHosts)
      CXX11_OVERRIDE;

  virtual void resetCounters() CXX11_OVERRIDE;
};

} // namespace aria2
#endif // D_MULTI_MIRROR_URI_SELECTOR_H
