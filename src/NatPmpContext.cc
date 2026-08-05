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
#include "NatPmpContext.h"

#include <cstring>
#include <vector>

#if defined(__APPLE__) || defined(__FreeBSD__) || defined(__DragonFly__)
#  include <sys/sysctl.h>
#  include <net/route.h>
#  include <netinet/in.h>
#elif defined(__linux__)
#  include <cstdio>
#elif defined(_WIN32)
#  include <winsock2.h>
#  include <iphlpapi.h>
#endif

#include "SocketCore.h"
#include "LogFactory.h"
#include "Logger.h"
#include "fmt.h"
#include "RecoverableException.h"
#include "a2netcompat.h"

namespace aria2 {

namespace {

// NAT-PMP port (RFC 6886 §3.1)。请求必须以单播发到默认网关——
// 发往组播地址（224.0.0.1）不会被网关应答（组播地址只用于网关
// 主动向 224.0.0.1:5350 广播地址变更通告）。
constexpr uint16_t PMP_PORT = 5351;

// RFC 6886 §3.1 建议 250ms 起指数退避至少 9 次重传（~64s）。本实现
// 在引擎启动期执行，不能阻塞太久；SocketCore::isReadable 粒度为秒，
// 采用 3 次尝试（1s + 1s + 2s，~4s 上限）。
constexpr int PMP_MAX_ATTEMPTS = 3;

// NAT-PMP opcodes.
constexpr unsigned char OP_MAP_TCP = 2;
// Response op = request op | 0x80.
constexpr unsigned char OP_MAP_TCP_RESPONSE = 0x80 | OP_MAP_TCP;
// Requested mapping lifetime in seconds (24h; gateways may clamp).
constexpr uint32_t MAPPING_LIFETIME = 24 * 60 * 60;

inline void appendBe16(unsigned char* p, uint16_t v)
{
  p[0] = static_cast<unsigned char>(v >> 8);
  p[1] = static_cast<unsigned char>(v & 0xFF);
}

inline uint16_t readBe16(const unsigned char* p)
{
  return static_cast<uint16_t>((p[0] << 8) | p[1]);
}

// 获取 IPv4 默认网关地址（RFC 6886 要求单播到默认网关）。
bool getDefaultGateway(std::string& out)
{
#if defined(__APPLE__) || defined(__FreeBSD__) || defined(__DragonFly__)
  int mib[6] = {CTL_NET, AF_ROUTE, 0, AF_INET, NET_RT_FLAGS, RTF_GATEWAY};
  size_t len = 0;
  if (sysctl(mib, 6, nullptr, &len, nullptr, 0) < 0 || len == 0) {
    return false;
  }
  std::vector<char> buf(len);
  if (sysctl(mib, 6, buf.data(), &len, nullptr, 0) < 0) {
    return false;
  }
  for (char* next = buf.data(); next < buf.data() + len;) {
    auto* rtm = reinterpret_cast<rt_msghdr*>(next);
    next += rtm->rtm_msglen;
    if (!(rtm->rtm_flags & RTF_GATEWAY)) {
      continue;
    }
    auto* sa = reinterpret_cast<sockaddr*>(rtm + 1);
    sockaddr* dst = nullptr;
    sockaddr* gate = nullptr;
    for (int i = 0; i < RTAX_MAX; ++i) {
      if (!(rtm->rtm_addrs & (1 << i))) {
        continue;
      }
      if (i == RTAX_DST) {
        dst = sa;
      }
      else if (i == RTAX_GATEWAY) {
        gate = sa;
      }
      // sockaddr 按 4 字节对齐步进
      size_t salen = sa->sa_len == 0 ? sizeof(uint32_t) : sa->sa_len;
      salen = (salen + sizeof(uint32_t) - 1) & ~(sizeof(uint32_t) - 1);
      sa = reinterpret_cast<sockaddr*>(reinterpret_cast<char*>(sa) + salen);
    }
    if (!dst || !gate || dst->sa_family != AF_INET ||
        gate->sa_family != AF_INET) {
      continue;
    }
    auto* d = reinterpret_cast<sockaddr_in*>(dst);
    if (d->sin_addr.s_addr != 0) {
      continue; // 非默认路由
    }
    auto* g = reinterpret_cast<sockaddr_in*>(gate);
    char addr[NI_MAXHOST];
    if (inetNtop(AF_INET, &g->sin_addr, addr, sizeof(addr))) {
      out = addr;
      return true;
    }
  }
  return false;
#elif defined(__linux__)
  // /proc/net/route: Iface Destination Gateway Flags ...（十六进制，
  // 小端）。Destination==00000000 且 Flags 含 RTF_GATEWAY(0x2) 即
  // 默认路由。
  FILE* fp = std::fopen("/proc/net/route", "r");
  if (!fp) {
    return false;
  }
  char line[256];
  bool found = false;
  // 跳过表头
  if (std::fgets(line, sizeof(line), fp)) {
    while (std::fgets(line, sizeof(line), fp)) {
      char iface[32];
      unsigned int dest, gate, flags;
      if (std::sscanf(line, "%31s %x %x %x", iface, &dest, &gate,
                      &flags) != 4) {
        continue;
      }
      if (dest != 0 || !(flags & 0x2)) {
        continue;
      }
      struct in_addr ga;
      ga.s_addr = gate; // /proc 里就是网络序的小端十六进制
      char addr[NI_MAXHOST];
      if (inetNtop(AF_INET, &ga, addr, sizeof(addr))) {
        out = addr;
        found = true;
      }
      break;
    }
  }
  std::fclose(fp);
  return found;
#elif defined(_WIN32)
  ULONG size = 0;
  if (GetAdaptersInfo(nullptr, &size) != ERROR_BUFFER_OVERFLOW) {
    return false;
  }
  std::vector<char> buf(size);
  auto* info = reinterpret_cast<IP_ADAPTER_INFO*>(buf.data());
  if (GetAdaptersInfo(info, &size) != NO_ERROR) {
    return false;
  }
  for (auto* p = info; p; p = p->Next) {
    if (p->GatewayList.IpAddress.String[0] == '\0') {
      continue;
    }
    out = p->GatewayList.IpAddress.String;
    return true;
  }
  return false;
#else
  (void)out;
  return false;
#endif
}

} // namespace

bool NatPmpContext::attemptedAny_ = false;

NatPmpContext::NatPmpContext() = default;

NatPmpContext& getNatPmpContext()
{
  static NatPmpContext ctx;
  return ctx;
}

bool NatPmpContext::alreadyAttempted() { return attemptedAny_; }

bool NatPmpContext::exchange(const std::string& gateway,
                             const unsigned char* req, size_t reqLen,
                             unsigned char* resp, size_t respCap,
                             size_t& respLen)
{
  std::shared_ptr<SocketCore> udp;
  try {
    udp = std::make_shared<SocketCore>(SOCK_DGRAM);
    udp->bindWithFamily(0, AF_INET);
  }
  catch (RecoverableException& e) {
    A2_LOG_DEBUG(fmt("NAT-PMP: socket init failed: %s", e.what()));
    return false;
  }

  // RFC 6886 §3.1：客户端应重传请求（指数退避）。UDP 丢包或网关
  // 繁忙时单次请求很容易超时，这里做 3 次尝试（~4s 上限），仍在
  // 引擎启动 NAT 遍历的时间预算内。
  static const time_t WAITS[PMP_MAX_ATTEMPTS] = {1, 1, 2};
  for (int attempt = 0; attempt < PMP_MAX_ATTEMPTS; ++attempt) {
    try {
      udp->writeData(req, reqLen, gateway, PMP_PORT);
    }
    catch (RecoverableException& e) {
      A2_LOG_DEBUG(fmt("NAT-PMP: request send failed: %s", e.what()));
      return false;
    }

    if (!udp->isReadable(WAITS[attempt])) {
      continue;
    }
    Endpoint sender;
    ssize_t n = 0;
    try {
      n = udp->readDataFrom(resp, respCap, sender);
    }
    catch (RecoverableException&) {
      return false;
    }
    if (n <= 0) {
      return false;
    }
    respLen = static_cast<size_t>(n);
    return true;
  }
  return false;
}

bool NatPmpContext::addPortMapping(uint16_t port)
{
  if (attemptedAny_) {
    return mapped_;
  }
  attemptedAny_ = true;
  attempted_ = true;

  if (port == 0) {
    A2_LOG_WARN("NAT-PMP: no valid port to map, skipping");
    return false;
  }

  // RFC 6886 §3.1：请求必须单播到默认网关。
  std::string gateway;
  if (!getDefaultGateway(gateway)) {
    A2_LOG_INFO("NAT-PMP: cannot determine default gateway, skipping");
    return false;
  }

  // Map request (RFC 6886 §3.3):
  //   [ver=0][op=2 (TCP)][2B reserved][2B internal port]
  //   [2B external port][4B lifetime]
  unsigned char req[12] = {0, OP_MAP_TCP};
  appendBe16(req + 2, 0);       // reserved
  appendBe16(req + 4, port);    // internal port
  appendBe16(req + 6, port);    // requested external port
  req[8] = static_cast<unsigned char>(MAPPING_LIFETIME >> 24);
  req[9] = static_cast<unsigned char>(MAPPING_LIFETIME >> 16);
  req[10] = static_cast<unsigned char>(MAPPING_LIFETIME >> 8);
  req[11] = static_cast<unsigned char>(MAPPING_LIFETIME & 0xFF);

  unsigned char resp[16];
  size_t respLen = 0;
  if (!exchange(gateway, req, sizeof(req), resp, sizeof(resp), respLen)) {
    A2_LOG_INFO("NAT-PMP: no gateway response (NAT traversal via "
                "NAT-PMP unavailable)");
    return false;
  }

  // Reply (RFC 6886 §3.3): [ver=0][op=0x82][2B result code][4B epoch]
  //   [2B internal port][2B external port][4B lifetime]，共 16 字节。
  // 注意：成功判定看 result code（bytes 2-3），不是 op 的高位——op
  // 高位只表示"这是响应"，错误响应同样置位。
  if (respLen < 16 || resp[0] != 0 || resp[1] != OP_MAP_TCP_RESPONSE) {
    A2_LOG_WARN("NAT-PMP: malformed gateway reply");
    return false;
  }
  uint16_t resultCode = readBe16(resp + 2);
  if (resultCode != 0) {
    A2_LOG_WARN(fmt("NAT-PMP: gateway rejected mapping, result code %u",
                    static_cast<unsigned>(resultCode)));
    return false;
  }
  // 网关可能分配了与请求不同的外部端口，以应答为准。
  uint16_t assignedPort = readBe16(resp + 10);

  mapped_ = true;
  mappedPort_ = assignedPort;
  A2_LOG_INFO(fmt("NAT-PMP: TCP port %u mapped on gateway %s (external "
                  "port %u, 24h lease)",
                  static_cast<unsigned>(port), gateway.c_str(),
                  static_cast<unsigned>(assignedPort)));
  return true;
}

void NatPmpContext::removePortMapping()
{
  if (!mapped_ || mappedPort_ == 0) {
    return;
  }
  std::string gateway;
  if (!getDefaultGateway(gateway)) {
    mapped_ = false;
    return;
  }
  // Delete = map request with lifetime 0.
  unsigned char req[12] = {0, OP_MAP_TCP};
  appendBe16(req + 2, 0);
  appendBe16(req + 4, mappedPort_);
  appendBe16(req + 6, mappedPort_);
  // lifetime stays zero → delete
  unsigned char resp[16];
  size_t respLen = 0;
  if (exchange(gateway, req, sizeof(req), resp, sizeof(resp), respLen)) {
    A2_LOG_INFO("NAT-PMP: port mapping removed on engine shutdown");
  }
  mapped_ = false;
}

} // namespace aria2
