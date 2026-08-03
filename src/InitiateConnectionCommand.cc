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
#include "InitiateConnectionCommand.h"
#include "Request.h"
#include "DownloadEngine.h"
#include "Option.h"
#include "Logger.h"
#include "LogFactory.h"
#include "message.h"
#include "prefs.h"
#include "NameResolver.h"
#include "SocketCore.h"
#include "FileEntry.h"
#include "RequestGroup.h"
#include "Segment.h"
#include "a2functional.h"
#include "InitiateConnectionCommandFactory.h"
#include "util.h"
#include "RecoverableException.h"
#include "fmt.h"
#include "SocketRecvBuffer.h"
#include "BackupIPv4ConnectCommand.h"
#include "ConnectCommand.h"
#include <algorithm>
#include <chrono>
#include <map>
#include <thread>
#include <future>
#include <vector>

namespace aria2 {

// 快速连接探测结构
struct ConnectionProbeResult {
  std::string ipaddr;
  int64_t latencyMs;  // 连接延迟（毫秒）
  bool success;
  
  ConnectionProbeResult() : latencyMs(-1), success(false) {}
  ConnectionProbeResult(const std::string& ip, int64_t latency, bool succ)
    : ipaddr(ip), latencyMs(latency), success(succ) {}
};

namespace {
// Probe-result cache keyed by "hostname:port". The first connection to a
// multi-IP host pays one round of parallel probing; every subsequent
// connection reuses the winner. Without this, each new segment
// connection spawned N std::async threads and blocked the event loop for
// up to the full probe timeout waiting on future.get(), and the probes
// were thrown away immediately (the chosen IP was re-connected from
// scratch).
struct FastestIpEntry {
  std::string ipaddr;
  std::chrono::steady_clock::time_point cachedAt;
};
std::map<std::string, FastestIpEntry> fastestIpCache;
constexpr auto FASTEST_IP_TTL = std::chrono::seconds(60);
} // namespace

// IP 合法性过滤：过滤掉私有地址、保留地址等
static bool isValidPublicIP(const std::string& ipaddr)
{
  char buf[sizeof(in6_addr)];
  
  // 检查 IPv4
  if (inetPton(AF_INET, ipaddr.c_str(), &buf) == 0) {
    uint32_t addr;
    memcpy(&addr, buf, sizeof(addr));
    addr = ntohl(addr);
    
    // 过滤私有地址和保留地址
    // 10.0.0.0/8
    if ((addr & 0xFF000000) == 0x0A000000) return false;
    // 172.16.0.0/12
    if ((addr & 0xFFF00000) == 0xAC100000) return false;
    // 192.168.0.0/16
    if ((addr & 0xFFFF0000) == 0xC0A80000) return false;
    // 127.0.0.0/8 (loopback)
    if ((addr & 0xFF000000) == 0x7F000000) return false;
    // 169.254.0.0/16 (link-local)
    if ((addr & 0xFFFF0000) == 0xA9FE0000) return false;
    // 0.0.0.0/8
    if ((addr & 0xFF000000) == 0x00000000) return false;
    // 224.0.0.0/4 (multicast)
    if ((addr & 0xF0000000) == 0xE0000000) return false;
    // 240.0.0.0/4 (reserved)
    if ((addr & 0xF0000000) == 0xF0000000) return false;
    
    return true;
  }
  
  // 检查 IPv6
  if (inetPton(AF_INET6, ipaddr.c_str(), &buf) == 0) {
    const uint8_t* addr6 = reinterpret_cast<const uint8_t*>(buf);
    
    // ::1 (loopback)
    bool isLoopback = true;
    for (int i = 0; i < 15; ++i) {
      if (addr6[i] != 0) {
        isLoopback = false;
        break;
      }
    }
    if (isLoopback && addr6[15] == 1) return false;
    
    // fe80::/10 (link-local)
    if (addr6[0] == 0xfe && (addr6[1] & 0xc0) == 0x80) return false;
    
    // fc00::/7 (unique local)
    if ((addr6[0] & 0xfe) == 0xfc) return false;
    
    // ff00::/8 (multicast)
    if (addr6[0] == 0xff) return false;
    
    return true;
  }
  
  return false;
}

// 快速连接探测：尝试连接到指定 IP，测量延迟
static ConnectionProbeResult probeConnection(const std::string& ipaddr, 
                                            uint16_t port,
                                            int timeoutMs = 800)
{
  ConnectionProbeResult result;
  result.ipaddr = ipaddr;
  
  try {
    auto socket = std::make_shared<SocketCore>();
    socket->create(AF_UNSPEC);
    socket->setNonBlockingMode();
    
    auto startTime = std::chrono::steady_clock::now();
    
    // 尝试连接
    socket->establishConnection(ipaddr, port, false);
    
    // 等待连接完成或超时
    fd_set writeSet;
    fd_set exceptSet;
    FD_ZERO(&writeSet);
    FD_ZERO(&exceptSet);
    FD_SET(socket->getSockfd(), &writeSet);
    FD_SET(socket->getSockfd(), &exceptSet);
    
    struct timeval tv;
    tv.tv_sec = timeoutMs / 1000;
    tv.tv_usec = (timeoutMs % 1000) * 1000;
    
    int selectResult = select(socket->getSockfd() + 1, nullptr, &writeSet, &exceptSet, &tv);
    
    if (selectResult > 0 && FD_ISSET(socket->getSockfd(), &writeSet)) {
      // 检查连接是否真的成功
      std::string error = socket->getSocketError();
      if (error.empty()) {
        auto endTime = std::chrono::steady_clock::now();
        result.latencyMs = std::chrono::duration_cast<std::chrono::milliseconds>(
          endTime - startTime).count();
        result.success = true;
      }
    }
    
    socket->closeConnection();
  }
  catch (...) {
    // 连接失败
  }
  
  return result;
}

InitiateConnectionCommand::InitiateConnectionCommand(
    cuid_t cuid, const std::shared_ptr<Request>& req,
    const std::shared_ptr<FileEntry>& fileEntry, RequestGroup* requestGroup,
    DownloadEngine* e)
    : AbstractCommand(cuid, req, fileEntry, requestGroup, e)
{
  setTimeout(std::chrono::seconds(getOption()->getAsInt(PREF_DNS_TIMEOUT)));
  // give a chance to be executed in the next loop in DownloadEngine
  setStatus(Command::STATUS_ONESHOT_REALTIME);
  disableReadCheckSocket();
  disableWriteCheckSocket();
}

InitiateConnectionCommand::~InitiateConnectionCommand() = default;

bool InitiateConnectionCommand::executeInternal()
{
  std::string hostname;
  uint16_t port;
  std::shared_ptr<Request> proxyRequest = createProxyRequest();
  
  if (!proxyRequest) {
    // No proxy: resolve target hostname and connect directly
    hostname = getRequest()->getHost();
    port = getRequest()->getPort();
    
    A2_LOG_INFO(fmt("CUID#%" PRId64 " - No proxy, resolving target %s:%u",
                    getCuid(), hostname.c_str(), port));
  }
  else {
    // Using proxy: only resolve proxy hostname, NOT target hostname
    // The proxy will resolve the target hostname itself
    hostname = proxyRequest->getHost();
    port = proxyRequest->getPort();
    
    A2_LOG_INFO(fmt("CUID#%" PRId64 " - Using proxy %s:%u for target %s:%u",
                    getCuid(), hostname.c_str(), port,
                    getRequest()->getHost().c_str(), getRequest()->getPort()));
  }
  
  // 步骤 1: 使用系统 DNS 解析主机名
  std::vector<std::string> allAddrs;
  std::string ipaddr = resolveHostname(allAddrs, hostname, port);
  if (ipaddr.empty()) {
    addCommandSelf();
    return false;
  }
  
  A2_LOG_INFO(fmt("CUID#%" PRId64 " - DNS resolved %zu addresses for %s",
                  getCuid(), allAddrs.size(), hostname.c_str()));
  
  // 步骤 2: IP 合法性过滤
  std::vector<std::string> validAddrs;
  for (const auto& addr : allAddrs) {
    if (isValidPublicIP(addr)) {
      validAddrs.push_back(addr);
      A2_LOG_DEBUG(fmt("CUID#%" PRId64 " - Valid IP: %s",
                       getCuid(), addr.c_str()));
    } else {
      A2_LOG_DEBUG(fmt("CUID#%" PRId64 " - Filtered out private/reserved IP: %s",
                       getCuid(), addr.c_str()));
    }
  }
  
  // 如果所有 IP 都被过滤了，使用原始列表（可能是内网环境）
  if (validAddrs.empty()) {
    A2_LOG_INFO(fmt("CUID#%" PRId64 " - All IPs filtered, using original list",
                    getCuid()));
    validAddrs = allAddrs;
  }
  
  // 步骤 3: 快速连接探测（并发）
  std::string bestIpaddr;
  const std::string cacheKey = hostname + ":" + util::uitos(port);
  const auto now = std::chrono::steady_clock::now();

  // 复用此前的探测结果（60s TTL），避免每个新连接都启动线程探测并
  // 阻塞事件循环等待 future.get()。
  auto cachedIt = fastestIpCache.find(cacheKey);
  if (cachedIt != fastestIpCache.end() &&
      now - cachedIt->second.cachedAt < FASTEST_IP_TTL &&
      std::find(validAddrs.begin(), validAddrs.end(),
                cachedIt->second.ipaddr) != validAddrs.end()) {
    bestIpaddr = cachedIt->second.ipaddr;
    A2_LOG_INFO(fmt("CUID#%" PRId64 " - Reusing cached fastest IP %s for %s",
                    getCuid(), bestIpaddr.c_str(), hostname.c_str()));
  }
  else if (validAddrs.size() == 1) {
    // 只有一个 IP，直接使用
    bestIpaddr = validAddrs[0];
    A2_LOG_INFO(fmt("CUID#%" PRId64 " - Only one IP available: %s",
                    getCuid(), bestIpaddr.c_str()));
  }
  else {
    // 多个 IP，进行并发探测（仅首次；后续连接复用缓存结果）
    A2_LOG_INFO(fmt("CUID#%" PRId64 " - Probing %zu IPs concurrently",
                    getCuid(), validAddrs.size()));
    
    std::vector<std::future<ConnectionProbeResult>> futures;
    
    // 启动并发探测
    for (const auto& addr : validAddrs) {
      futures.push_back(std::async(std::launch::async, probeConnection, addr, port, 500));
    }
    
    // 收集结果
    std::vector<ConnectionProbeResult> results;
    for (auto& future : futures) {
      try {
        results.push_back(future.get());
      } catch (...) {
        // 忽略异常
      }
    }
    
    // 步骤 4: 选择最快的通道
    ConnectionProbeResult* bestResult = nullptr;
    for (auto& result : results) {
      if (result.success) {
        if (!bestResult || result.latencyMs < bestResult->latencyMs) {
          bestResult = &result;
        }
        A2_LOG_INFO(fmt("CUID#%" PRId64 " - IP %s: latency %lld ms",
                        getCuid(), result.ipaddr.c_str(), 
                        static_cast<long long>(result.latencyMs)));
      } else {
        A2_LOG_DEBUG(fmt("CUID#%" PRId64 " - IP %s: probe failed",
                         getCuid(), result.ipaddr.c_str()));
      }
    }
    
    if (bestResult) {
      bestIpaddr = bestResult->ipaddr;
      A2_LOG_INFO(fmt("CUID#%" PRId64 " - Selected fastest IP: %s (latency: %lld ms)",
                      getCuid(), bestIpaddr.c_str(), 
                      static_cast<long long>(bestResult->latencyMs)));
    } else {
      // 所有探测都失败，使用第一个 IP
      bestIpaddr = validAddrs[0];
      A2_LOG_INFO(fmt("CUID#%" PRId64 " - All probes failed, using first IP: %s",
                      getCuid(), bestIpaddr.c_str()));
    }
  }

  // 记住本次选择，供同 host 的后续连接复用
  fastestIpCache[cacheKey] = {bestIpaddr, now};
  
  // 步骤 5: 使用选定的最快 IP 进行正式下载
  try {
    auto c = createNextCommand(hostname, bestIpaddr, port, validAddrs, proxyRequest);
    c->setStatus(Command::STATUS_ONESHOT_REALTIME);
    getDownloadEngine()->setNoWait(true);
    getDownloadEngine()->addCommand(std::move(c));
    return true;
  }
  catch (RecoverableException& ex) {
    // Catch exception and retry another address.
    // See also AbstractCommand::checkIfConnectionEstablished

    // Invalidate the probe cache so a failed IP is not reused.
    fastestIpCache.erase(cacheKey);

    // TODO ipaddr might not be used if pooled socket was found.
    getDownloadEngine()->markBadIPAddress(hostname, bestIpaddr, port);
    if (!getDownloadEngine()->findCachedIPAddress(hostname, port).empty()) {
      A2_LOG_INFO_EX(EX_EXCEPTION_CAUGHT, ex);
      A2_LOG_INFO(
          fmt(MSG_CONNECT_FAILED_AND_RETRY, getCuid(), bestIpaddr.c_str(), port));
      auto command =
          InitiateConnectionCommandFactory::createInitiateConnectionCommand(
              getCuid(), getRequest(), getFileEntry(), getRequestGroup(),
              getDownloadEngine());
      getDownloadEngine()->setNoWait(true);
      getDownloadEngine()->addCommand(std::move(command));
      return true;
    }
    getDownloadEngine()->removeCachedIPAddress(hostname, port);
    throw;
  }
}

void InitiateConnectionCommand::setConnectedAddrInfo(
    const std::shared_ptr<Request>& req, const std::string& hostname,
    const std::shared_ptr<SocketCore>& socket)
{
  auto endpoint = socket->getPeerInfo();
  req->setConnectedAddrInfo(hostname, endpoint.addr, endpoint.port);
}

std::shared_ptr<BackupConnectInfo>
InitiateConnectionCommand::createBackupIPv4ConnectCommand(
    const std::string& hostname, const std::string& ipaddr, uint16_t port,
    Command* mainCommand)
{
  // Prepare IPv4 backup connection attempt in "Happy Eyeballs"
  // fashion.
  std::shared_ptr<BackupConnectInfo> info;
  char buf[sizeof(in6_addr)];
  if (inetPton(AF_INET6, ipaddr.c_str(), &buf) == -1) {
    return info;
  }
  A2_LOG_INFO("Searching IPv4 address for backup connection attempt");
  std::vector<std::string> addrs;
  getDownloadEngine()->findAllCachedIPAddresses(std::back_inserter(addrs),
                                                hostname, port);
  for (std::vector<std::string>::const_iterator i = addrs.begin(),
                                                eoi = addrs.end();
       i != eoi; ++i) {
    if (inetPton(AF_INET, (*i).c_str(), &buf) == 0) {
      info = std::make_shared<BackupConnectInfo>();
      auto command = make_unique<BackupIPv4ConnectCommand>(
          getDownloadEngine()->newCUID(), *i, port, info, mainCommand,
          getRequestGroup(), getDownloadEngine());
      A2_LOG_INFO(fmt("Issue backup connection command CUID#%" PRId64
                      ", addr=%s",
                      command->getCuid(), (*i).c_str()));
      getDownloadEngine()->addCommand(std::move(command));
      return info;
    }
  }
  return info;
}

void InitiateConnectionCommand::setupBackupConnection(
    const std::string& hostname, const std::string& addr, uint16_t port,
    ConnectCommand* c)
{
  std::shared_ptr<BackupConnectInfo> backupConnectInfo =
      createBackupIPv4ConnectCommand(hostname, addr, port, c);
  if (backupConnectInfo) {
    c->setBackupConnectInfo(backupConnectInfo);
  }
}

} // namespace aria2
