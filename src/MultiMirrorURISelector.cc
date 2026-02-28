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

  // 找到使用次数最少的 URI
  std::vector<std::pair<int, std::string>> candidates;
  
  for (const auto& uri : uris) {
    uri_split_result us;
    if (uri_split(&us, uri.c_str()) != 0) {
      continue;
    }
    
    std::string host = uri::getFieldString(us, USR_HOST, uri.c_str());
    std::string protocol = uri::getFieldString(us, USR_SCHEME, uri.c_str());
    
    // 获取这个 URI 已经被选择的次数
    int selectionCount = 0;
    auto it = uriSelectionCount_.find(uri);
    if (it != uriSelectionCount_.end()) {
      selectionCount = it->second;
    }
    
    // 检查这个主机当前有多少个连接在使用
    int currentHostConnections = 0;
    for (const auto& usedHost : usedHosts) {
      if (usedHost.second == host) {
        currentHostConnections++;
      }
    }
    
    // 获取服务器统计信息
    std::shared_ptr<ServerStat> ss = serverStatMan_->find(host, protocol);
    int speed = 0;
    if (ss) {
      speed = std::max(ss->getSingleConnectionAvgSpeed(),
                      ss->getMultiConnectionAvgSpeed());
    }
    
    // 优先级计算：
    // 1. 选择次数少的 URI 优先（主要因素）
    // 2. 当前连接数少的主机优先（次要因素）
    // 3. 速度快的服务器优先（辅助因素）
    int priority = (-selectionCount * 100000000) + (-currentHostConnections * 1000000) + speed;
    
    candidates.push_back(std::make_pair(priority, uri));
    
    A2_LOG_DEBUG(fmt("MultiMirrorURISelector: URI %s, selections=%d, currentConns=%d, speed=%d, priority=%d",
                     uri.c_str(), selectionCount, currentHostConnections, speed, priority));
  }
  
  if (candidates.empty()) {
    A2_LOG_DEBUG("MultiMirrorURISelector: no candidates available");
    return A2STR::NIL;
  }
  
  // 按优先级排序（最高优先级在前）
  std::sort(candidates.begin(), candidates.end(),
            [](const std::pair<int, std::string>& a,
               const std::pair<int, std::string>& b) {
              return a.first > b.first;
            });
  
  std::string selected = candidates.front().second;
  A2_LOG_DEBUG(fmt("MultiMirrorURISelector: selected %s from %lu candidates",
                   selected.c_str(), static_cast<unsigned long>(candidates.size())));
  
  return selected;
}

std::string MultiMirrorURISelector::select(
    FileEntry* fileEntry,
    const std::vector<std::pair<size_t, std::string>>& usedHosts)
{
  A2_LOG_DEBUG(fmt("MultiMirrorURISelector: selecting URI"));
  
  std::string selected = selectBestAvailableUri(fileEntry, usedHosts);
  
  if (selected != A2STR::NIL) {
    // 记录这个 URI 被选择了
    uriSelectionCount_[selected]++;
    
    A2_LOG_DEBUG(fmt("MultiMirrorURISelector: selected URI: %s (total selections: %d)", 
                     selected.c_str(), uriSelectionCount_[selected]));
  }
  else {
    A2_LOG_DEBUG("MultiMirrorURISelector: no available URI found");
  }
  
  return selected;
}

void MultiMirrorURISelector::resetCounters()
{
  uriSelectionCount_.clear();
  A2_LOG_DEBUG("MultiMirrorURISelector: counters reset");
}

} // namespace aria2
