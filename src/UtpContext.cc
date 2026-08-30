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
#include "UtpContext.h"

#include <chrono>

#include "SocketCore.h"
#include "UtpConnection.h"
#include "a2functional.h"
#include "UtpPacket.h"
#include "LogFactory.h"
#include "Logger.h"
#include "fmt.h"
#include "RecoverableException.h"

namespace aria2 {
namespace utp {

namespace {
constexpr size_t MAX_DATAGRAM = 2048;
}

UtpContext::UtpContext() = default;

UtpContext::~UtpContext() = default;

uint32_t UtpContext::nowUs()
{
  using namespace std::chrono;
  auto now = steady_clock::now().time_since_epoch();
  return static_cast<uint32_t>(
      duration_cast<microseconds>(now).count() & 0xFFFFFFFF);
}

bool UtpContext::start(uint16_t port)
{
  if (started_) {
    return true;
  }
  try {
    socket_ = std::make_shared<SocketCore>(SOCK_DGRAM);
    try {
      // 标准 BT 约定：uTP 与 TCP 监听同端口，对端才会把 uTP SYN 发到
      // 我们通告的监听端口。绑定失败（端口被占用）时回退临时端口，
      // 至少保证出站 uTP 可用。
      socket_->bindWithFamily(port, AF_INET);
    }
    catch (RecoverableException&) {
      if (port != 0) {
        A2_LOG_WARN(fmt("uTP: port %u busy, falling back to ephemeral",
                        static_cast<unsigned>(port)));
        socket_->bindWithFamily(0, AF_INET);
      }
      else {
        throw;
      }
    }
    socket_->setNonBlockingMode();
    started_ = true;
    A2_LOG_INFO(fmt("uTP: UDP socket bound on port %u",
                    static_cast<unsigned>(socket_->getAddrInfo().port)));
    return true;
  }
  catch (RecoverableException& e) {
    A2_LOG_WARN(fmt("uTP: failed to bind UDP socket: %s", e.what()));
    socket_.reset();
    return false;
  }
}

std::shared_ptr<UtpConnection> UtpContext::connect(const std::string& addr,
                                                   uint16_t port,
                                                   uint32_t synTimeoutUs)
{
  if (!started_) {
    return nullptr;
  }
  // recvId 来自随机数：同微秒多次 connect 或与既有连接撞 id 时，
  // emplace 会静默失败（连接不在注册表，其 SYN 永远发不出去）。
  // 必须重试直至注册成功。
  for (int attempt = 0; attempt < 8; ++attempt) {
    auto conn =
        std::make_shared<UtpConnection>(addr, port, nowUs(), synTimeoutUs);
    if (connections_.emplace(conn->getRecvId(), conn).second) {
      return conn;
    }
  }
  return nullptr;
}

void UtpContext::processTick()
{
  if (!started_) {
    return;
  }
  uint32_t now = nowUs();

  // 1. Advance every connection (timers, retransmit, CC-gated flush).
  for (auto& kv : connections_) {
    kv.second->processTick(now);
  }

  // 2. Flush outboxes over the shared UDP socket. 必须在删除死连接
  // 之前执行：本 tick 刚 CLOSED 的连接其 outbox 里可能还有最后一
  // 包（如对端 FIN 的最终 ACK），先删后 flush 会把它丢掉，导致对端
  // 重传 FIN 直至超时。
  for (auto& kv : connections_) {
    flushOutbox(kv.second.get());
  }

  // 3. Remove dead connections.
  for (auto it = connections_.begin(); it != connections_.end();) {
    auto& conn = it->second;
    if (conn->isClosed() || conn->hasError()) {
      it = connections_.erase(it);
    }
    else {
      ++it;
    }
  }
}

void UtpContext::receiveLoop()
{
  if (!started_ || !socket_) {
    return;
  }
  unsigned char buf[MAX_DATAGRAM];
  while (true) {
    Endpoint sender;
    ssize_t n = 0;
    try {
      n = socket_->readDataFrom(buf, sizeof(buf), sender);
    }
    catch (RecoverableException&) {
      break;
    }
    if (n <= 0) {
      break; // EAGAIN or no more data
    }

    PacketHeader hdr;
    std::vector<std::pair<uint8_t, std::vector<uint8_t>>> exts;
    if (!parsePacket(buf, static_cast<size_t>(n), hdr, exts)) {
      continue;
    }

    // 按包头 connection_id 查找目标连接：连接以各自的接收匹配键
    // （recvId_）注册——发起方注册自己的 recv_id（= SYN.conn_id），
    // 响应方注册 SYN.conn_id + 1（发起方数据包携带该值）。
    UtpConnection* conn = find(hdr.connectionId);
    if (!conn && hdr.type == ST_SYN) {
      // 重发的 SYN 携带 SYN.conn_id = 响应方的 sendId_，不会命中按
      // recvId_ 的注册；回找已接受该 SYN 的连接，交给它重发 SYN-ACK，
      // 避免把重传 SYN 误当新连接重复建链。
      conn = findBySendId(hdr.connectionId);
    }
    if (conn) {
      conn->handlePacket(buf, static_cast<size_t>(n), nowUs());
      // 立即把本次分发产生的 ACK/响应发出去：若等下一轮
      // processTick，无后续入站包时引擎要阻塞到刷新间隔（1s）才发，
      // 对端窗口换轮被拉长 1s，吞吐只剩几十 KB。
      flushOutbox(conn);
      continue;
    }

    // Unknown connection id. A SYN starts a new inbound connection.
    if (hdr.type == ST_SYN) {
      auto incoming = std::make_shared<UtpConnection>(
          sender.addr, sender.port, hdr.connectionId, hdr.seqNr, nowUs());
      // 注册失败（recvId 冲突）时不能回调 acceptHandler，否则会产生
      // 一个永不被 tick 的僵尸连接。
      if (!connections_.emplace(incoming->getRecvId(), incoming).second) {
        continue;
      }
      A2_LOG_INFO(fmt("uTP: accepted inbound SYN from %s:%u (recvId=%u)",
                      sender.addr.c_str(), sender.port,
                      static_cast<unsigned>(incoming->getRecvId())));
      // SYN-ACK 立即发出（构造函数已入队），不等下一轮迭代。
      flushOutbox(incoming.get());
      if (acceptHandler_) {
        acceptHandler_(incoming);
      }
    }
    // else: datagram for a connection we already closed — drop (a
    // production impl would answer RESET; the peer times out instead).
  }
}

UtpConnection* UtpContext::find(uint16_t recvId)
{
  auto it = connections_.find(recvId);
  return it == connections_.end() ? nullptr : it->second.get();
}

UtpConnection* UtpContext::findBySendId(uint16_t sendId)
{
  // 仅用于 SYN 重传路由，连接数有限时线性扫描足够。
  for (auto& kv : connections_) {
    if (kv.second && kv.second->getSendId() == sendId) {
      return kv.second.get();
    }
  }
  return nullptr;
}

void UtpContext::removeConnection(UtpConnection* conn)
{
  if (!conn) {
    return;
  }
  connections_.erase(conn->getRecvId());
}

void UtpContext::flushOutbox(UtpConnection* conn)
{
  if (!conn) {
    return;
  }
  std::vector<std::vector<unsigned char>> out;
  conn->drainOutbox(out);
  for (auto& pkt : out) {
    sendDatagram(pkt.data(), pkt.size(), conn->getRemoteAddr(),
                 conn->getRemotePort());
  }
}

void UtpContext::sendDatagram(const unsigned char* data, size_t len,
                              const std::string& addr, uint16_t port)
{
  if (!socket_) {
    return;
  }
  try {
    socket_->writeData(data, len, addr, port);
  }
  catch (RecoverableException& e) {
    A2_LOG_DEBUG(fmt("uTP: send to %s:%u failed: %s", addr.c_str(), port,
                     e.what()));
  }
}

} // namespace utp
} // namespace aria2
