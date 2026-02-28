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
#include "MultiMirrorURISelector.h"

#include <algorithm>

#include "RequestGroup.h"
#include "ServerStatMan.h"
#include "ServerStat.h"
#include "FileEntry.h"
#include "Logger.h"
#include "LogFactory.h"
#include "A2STR.h"
#include "uri.h"
#include "fmt.h"

namespace aria2 {

MultiMirrorURISelector::MultiMirrorURISelector(
    std::shared_ptr<ServerStatMan> serverStatMan, RequestGroup* requestGroup)
    : serverStatMan_(std::move(serverStatMan)), requestGroup_(requestGroup)
{
}

MultiMirrorURISelector::~MultiMirrorURISelector() = default;

std::string MultiMirrorURISelector::selectBestAvailableUri(
    FileEntry* fileEntry,
    const std::vector<std::pair<size_t, std::string>>& usedHosts)
{
  std::deque<std::string>& uris = fileEntry->getRemainingUris();
  
  if (uris.empty()) {
    return A2STR::NIL;
  }

  // Find URIs that are not currently being used by any connection
  std::vector<std::pair<int, std::string>> availableUris;
  
  for (const auto& uri : uris) {
    uri_split_result us;
    if (uri_split(&us, uri.c_str()) != 0) {
      continue;
    }
    
    std::string host = uri::getFieldString(us, USR_HOST, uri.c_str());
    std::string protocol = uri::getFieldString(us, USR_SCHEME, uri.c_str());
    
    // Check if this URI is already being used
    auto it = uriToCuids_.find(uri);
    int currentUsers = (it != uriToCuids_.end()) ? it->second.size() : 0;
    
    // Skip if this host is in usedHosts
    bool hostUsed = false;
    for (const auto& usedHost : usedHosts) {
      if (usedHost.second == host) {
        hostUsed = true;
        break;
      }
    }
    
    if (hostUsed) {
      continue;
    }
    
    // Get server statistics for speed-based selection
    std::shared_ptr<ServerStat> ss = serverStatMan_->find(host, protocol);
    int speed = 0;
    if (ss) {
      speed = std::max(ss->getSingleConnectionAvgSpeed(),
                      ss->getMultiConnectionAvgSpeed());
    }
    
    // Prefer URIs that are not being used, then by speed
    // Priority: unused URIs with high speed > unused URIs > used URIs with high speed
    int priority = (currentUsers == 0 ? 1000000 : 0) + speed;
    
    availableUris.push_back(std::make_pair(priority, uri));
  }
  
  if (availableUris.empty()) {
    return A2STR::NIL;
  }
  
  // Sort by priority (highest first)
  std::sort(availableUris.begin(), availableUris.end(),
            [](const std::pair<int, std::string>& a,
               const std::pair<int, std::string>& b) {
              return a.first > b.first;
            });
  
  return availableUris.front().second;
}

std::string MultiMirrorURISelector::select(
    FileEntry* fileEntry,
    const std::vector<std::pair<size_t, std::string>>& usedHosts)
{
  A2_LOG_DEBUG(fmt("MultiMirrorURISelector: selecting URI for connection"));
  
  std::string selected = selectBestAvailableUri(fileEntry, usedHosts);
  
  if (selected != A2STR::NIL) {
    std::deque<std::string>& uris = fileEntry->getRemainingUris();
    uris.erase(std::find(std::begin(uris), std::end(uris), selected));
    
    A2_LOG_DEBUG(fmt("MultiMirrorURISelector: selected URI: %s", 
                     selected.c_str()));
  }
  else {
    A2_LOG_DEBUG("MultiMirrorURISelector: no available URI found");
  }
  
  return selected;
}

void MultiMirrorURISelector::resetCounters()
{
  uriToCuids_.clear();
  cuidToUri_.clear();
  A2_LOG_DEBUG("MultiMirrorURISelector: counters reset");
}

} // namespace aria2
