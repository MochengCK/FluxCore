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
#include "UtpConnection.h"

#include <algorithm>
#include <cstring>

#include "UtpPacket.h"

namespace aria2 {
namespace utp {

namespace {

// Payload cap per ST_DATA packet. Must keep the full UDP datagram
// (20B uTP header + payload + 8B UDP + 20B IPv4) below the 1500B MTU,
// otherwise the OS IP-fragments every packet — losing any fragment
// kills the whole datagram, and many NATs/firewalls drop fragments
// outright. 1400 leaves headroom for extensions/PPPoE links.
constexpr uint32_t DEFAULT_PACKET_SIZE = 1400;
constexpr uint32_t MIN_PACKET_SIZE = 150;
// Receive buffer cap; advertised to the peer as our flow-control window.
// 1MB：256KB 在高带宽×高延迟链路（如 200ms RTT 跨洲）会把对端发送
// 速率硬限制在 ~10Mbps；1MB 覆盖 ~40Mbps@200ms 的 BDP，内存上界
// 仍受 peer 数量约束。应用层每轮引擎循环即排空 recvOut_，实际驻留
// 远低于该上限。
constexpr uint32_t RECV_WINDOW = 1024 * 1024;
// LEDBAT target one-way delay (spec: CCONTROL_TARGET = 100ms).
constexpr uint32_t CC_TARGET_US = 100 * 1000;
// Base delay window (spec: 2 minutes).
constexpr uint32_t BASE_DELAY_WINDOW_US = 120 * 1000 * 1000;
// Max cwnd increase per RTT, in packets (spec: MAX_CWND_INCREASE_PER_RTT).
constexpr double MAX_CWND_INCREASE_PER_RTT = 1.0;
// RTO floor (spec: 500ms) and cap for doubling.
constexpr uint32_t RTO_MIN_US = 500 * 1000;
constexpr uint32_t RTO_MAX_US = 60 * 1000 * 1000;

// True if seq a is after b (wrap-safe).
inline bool seqAfter(uint16_t a, uint16_t b)
{
  return static_cast<int16_t>(a - b) > 0;
}

// True if seq a is before-or-equal b (wrap-safe).
inline bool seqLeq(uint16_t a, uint16_t b)
{
  return static_cast<int16_t>(a - b) <= 0;
}

uint32_t rand32(uint32_t seed)
{
  // xorshift32 — good enough for connection ids / responder seq.
  seed ^= seed << 13;
  seed ^= seed >> 17;
  seed ^= seed << 5;
  return seed;
}

} // namespace

UtpConnection::UtpConnection(const std::string& remoteAddr, uint16_t remotePort,
                             uint32_t nowUs, uint32_t synTimeoutUs)
    : remoteAddr_(remoteAddr), remotePort_(remotePort)
{
  initCommon(remoteAddr, remotePort);
  // BEP 29：发起方随机选择连接 id C，我方所有出站包（含 SYN）都
  // 使用 C；响应方所有出站包使用 C+1。因此匹配入站包的 recvId =
  // C+1，出站 sendId = C。此前两者颠倒（recv=C/send=C+1）：SYN 特
  // 券携带 recvId 碰巧正确，但 SYN-ACK 之后我方数据包带 C+1 会被
  // 对端（期望 C）丢弃，同时对端包（C+1）也无法命中我方连接注册
  // ——出站 uTP 与标准客户端永远无法完成握手，表现为"uTP 节点无
  // 客户端、无速度"的死链。
  sendId_ = static_cast<uint16_t>(rand32(nowUs));
  recvId_ = static_cast<uint16_t>(sendId_ + 1);
  seq_ = 1;
  peerWnd_ = 0x7FFFFFFFu;
  state_ = State::SYN_SENT;
  lastRecvUs_ = 0;
  lastSendUs_ = nowUs;
  if (synTimeoutUs > 0) {
    synDeadlineUs_ = nowUs + synTimeoutUs;
    synDeadlineValid_ = true;
  }
  // Queue the initial SYN (carries sendId_, like all our packets).
  queueControl(ST_SYN, nowUs, 0);
}

UtpConnection::UtpConnection(const std::string& remoteAddr, uint16_t remotePort,
                             uint16_t peerRecvId, uint16_t ackNr,
                             uint32_t nowUs)
    : remoteAddr_(remoteAddr), remotePort_(remotePort)
{
  initCommon(remoteAddr, remotePort);
  // BEP 29：响应方的入站包（对端发起方的所有包）携带 SYN 中的 id
  // peerRecvId；我方所有出站包使用 peerRecvId + 1。seq = random，
  // ack = SYN seq。此前 recv/send 颠倒：SYN-ACK 携带 peerRecvId 而
  // 对端期望 +1，握手同样无法完成。
  recvId_ = peerRecvId;
  sendId_ = static_cast<uint16_t>(peerRecvId + 1);
  seq_ = static_cast<uint16_t>(rand32(nowUs));
  ack_ = ackNr;
  peerWnd_ = 0x7FFFFFFFu;
  state_ = State::SYN_RECV;
  lastRecvUs_ = nowUs;
  lastSendUs_ = nowUs;
  // Reply with a pure ACK (ST_STATE), per spec.
  queueControl(ST_STATE, nowUs, ack_);
}

void UtpConnection::initCommon(const std::string& remoteAddr,
                               uint16_t remotePort)
{
  maxWindow_ = DEFAULT_PACKET_SIZE * 2;
  packetSize_ = DEFAULT_PACKET_SIZE;
  rtt_ = 0;
  rttVar_ = 0;
  timeout_ = 1000 * 1000; // spec: initial timeout 1s
  consecutiveTimeouts_ = 0;
  baseDelay_ = 0;
  baseDelaySetUs_ = 0;
}

UtpConnection::~UtpConnection() = default;

// ---------------------------------------------------------------------------
// Stream API
// ---------------------------------------------------------------------------

size_t UtpConnection::write(const unsigned char* data, size_t len)
{
  wantWrite_ = false;
  // 连接已关闭/出错：拒绝写入并返回 0（wantWrite 保持 false），
  // 让上层（SocketBuffer::send）按"连接已关闭"处理，而不是静默
  // 吞掉最多 1MB 数据成为黑洞。
  if (state_ == State::CLOSED || error_) {
    return 0;
  }
  // Bound the user-side buffer so a stuck peer cannot balloon memory.
  // Data actually leaves this buffer as soon as the CC window allows.
  constexpr size_t MAX_PENDING = 1024 * 1024;
  size_t accepted = 0;
  while (accepted < len && pendingSend_.size() < MAX_PENDING) {
    pendingSend_.push_back(data[accepted]);
    ++accepted;
  }
  if (accepted < len) {
    // 用户侧缓冲已满：属于 EAGAIN 语义——CC 窗口腾空后可继续写。
    // 必须置 wantWrite_，否则上层会把"部分写后写不动"误判为连接关闭。
    wantWrite_ = true;
  }
  return accepted;
}

size_t UtpConnection::read(unsigned char* data, size_t cap)
{
  wantRead_ = false;
  size_t n = 0;
  while (n < cap && !recvOut_.empty()) {
    data[n] = recvOut_.front();
    recvOut_.pop_front();
    ++n;
  }
  if (n == 0 && recvOut_.empty() && !eofReceived() && !isClosed() &&
      !hasError()) {
    // 缓冲区暂时为空但连接仍存活：EAGAIN 语义（置 wantRead_），
    // 不是 EOF。真正的 EOF 由 eofReceived()/isClosed()/hasError()
    // 表达——否则 BT 层（PeerConnection::receiveMessage）会在每次
    // 读空缓冲时误判对端关闭而断开连接。
    wantRead_ = true;
  }
  return n;
}

// ---------------------------------------------------------------------------
// Packet reception
// ---------------------------------------------------------------------------

void UtpConnection::handlePacket(const unsigned char* data, size_t len,
                                 uint32_t nowUs)
{
  PacketHeader hdr;
  std::vector<std::pair<uint8_t, std::vector<uint8_t>>> exts;
  if (!parsePacket(data, len, hdr, exts)) {
    return;
  }

  lastRecvUs_ = nowUs;
  consecutiveTimeouts_ = 0;
  // Timestamp bookkeeping for RTT/delay measurement.
  // BEP 29：timestamp_difference 必须在收包时刻冻结为
  // (本地收包时刻 - 对端包内时间戳)，随我方下一个包原样回显；
  // 单向延迟样本同样是本地时钟域的 (now - 对端时间戳)，时钟偏移
  // 由 baseDelay 的最小值过滤消除。此前把对端时钟减本地发送时刻
  // （混用两个时钟域，uint32 下溢后为天文数字），LEDBAT 延迟样本
  // 全是垃圾，cwnd 实际无反馈增长。
  lastPeerTs_ = hdr.timestamp;
  tsDiffEcho_ = nowUs - hdr.timestamp;
  // 对端通告 0 窗口是合法且关键的流控信号（收缓冲满），不能当成
  // "未通告"忽略——否则我们会持续向已满缓冲发包，造成丢包恶性循环。
  peerWnd_ = hdr.wndSize;
  if (hdr.type != ST_SYN) {
    updateDelay(tsDiffEcho_, nowUs);
  }
  // RTT 样本只取自 onAck 中"我方包发送时刻 → 收到其 ACK 时刻"，
  // 不做跨时钟域的 RTT 估算。

  uint32_t sackBits = 0;
  for (auto& e : exts) {
    if (e.first == EXT_SACK) {
      sackBits = decodeSackBits(e.second.data(), e.second.size());
    }
  }

  switch (hdr.type) {
  case ST_SYN: {
    // We are the responder; an inbound SYN on an existing connection id
    // is a retransmission — ignore (the SYN-ACK was already queued).
    if (state_ == State::SYN_RECV || state_ == State::CONNECTED) {
      queueControl(ST_STATE, nowUs, ack_);
    }
    break;
  }
  case ST_STATE:
  case ST_RESET: {
    if (hdr.type == ST_RESET) {
      error_ = true;
      state_ = State::CLOSED;
      return;
    }
    if (state_ == State::SYN_SENT) {
      // Our SYN was accepted: mark connected, adopt peer seq.
      ack_ = hdr.seqNr;
      synAcked_ = true;
      state_ = State::CONNECTED;
    }
    onAck(hdr.ackNr, sackBits, nowUs);
    break;
  }
  case ST_DATA:
  case ST_FIN: {
    if (state_ == State::SYN_RECV) {
      state_ = State::CONNECTED; // first data from initiator
    }
    else if (state_ == State::SYN_SENT) {
      ack_ = hdr.seqNr;
      synAcked_ = true;
      state_ = State::CONNECTED;
    }
    if (hdr.type == ST_DATA) {
      size_t extTotal = 0;
      for (const auto& e : exts) {
        extTotal += 2 + e.second.size();
      }
      const unsigned char* payload = data + HEADER_LEN + extTotal;
      size_t payloadLen = len >= HEADER_LEN + extTotal
                              ? len - HEADER_LEN - extTotal
                              : 0;
      onData(hdr, payload, payloadLen, nowUs);
    }
    else {
      // ST_FIN: FIN 占用一个序列号。按序到达时推进 ack_（累计确认
      // 包含 FIN），否则对端永远收不到 FIN 的确认而重传到超时；
      // 乱序 FIN 等数据补齐后由对端重传处理。
      if (hdr.seqNr == static_cast<uint16_t>(ack_ + 1) && !eof_) {
        ack_ = hdr.seqNr;
        eof_ = true;
        eofPkt_ = hdr.seqNr;
      }
      ackPending_ = true;
    }
    onAck(hdr.ackNr, sackBits, nowUs);
    break;
  }
  default:
    break;
  }

  // Schedule an ACK; flushed by processTick() (also on data packets we
  // send, piggybacked via ack_).
  if (ackPending_) {
    sendAck(nowUs);
  }
}

void UtpConnection::onData(const PacketHeader& hdr, const unsigned char* payload,
                           size_t payloadLen, uint32_t nowUs)
{
  uint16_t s = hdr.seqNr;
  if (payloadLen == 0) {
    return;
  }
  if (seqLeq(s, ack_)) {
    return; // duplicate / old
  }
  if (s == static_cast<uint16_t>(ack_ + 1)) {
    // Contiguous: deliver, then drain the reorder buffer.
    recvOut_.insert(recvOut_.end(), payload, payload + payloadLen);
    ack_ = s;
    while (!recvReorder_.empty()) {
      auto it = recvReorder_.begin();
      if (it->first != static_cast<uint16_t>(ack_ + 1)) {
        break;
      }
      auto& p = it->second;
      recvOut_.insert(recvOut_.end(), p.payload.begin(), p.payload.end());
      recvBuffered_ -= static_cast<uint32_t>(p.payload.size());
      ack_ = it->first;
      recvReorder_.erase(it);
    }
    ackPending_ = true;
  }
  else {
    // Out of order: buffer for SACK + later drain. Bound by window.
    if (recvBuffered_ + payloadLen <= RECV_WINDOW) {
      // 同一 seq 的重复乱序包：先扣除旧 entry 的字节数，否则
      // recvBuffered_ 只增不减，通告窗口会随重传单调收缩到 0。
      auto dup = recvReorder_.find(s);
      if (dup != recvReorder_.end()) {
        recvBuffered_ -= static_cast<uint32_t>(dup->second.payload.size());
        recvReorder_.erase(dup);
      }
      InPacket ip;
      ip.payload.assign(payload, payload + payloadLen);
      ip.receivedAtUs = nowUs;
      recvReorder_[s] = std::move(ip);
      recvBuffered_ += static_cast<uint32_t>(payloadLen);
    }
    ackPending_ = true; // advertise gap via SACK
  }
  wantRead_ = true;
}

void UtpConnection::onAck(uint16_t ackNr, uint32_t sackBits, uint32_t nowUs)
{
  if (state_ == State::SYN_SENT && !synAcked_) {
    return; // not connected yet; nothing to ack
  }

  // Track duplicate acks for fast retransmit (on ack_nr+1).
  if (ackNr == lastAckNr_) {
    ++dupAckCount_;
  }
  else {
    lastAckNr_ = ackNr;
    dupAckCount_ = 0;
  }

  // Remove acknowledged packets, update window + RTT.
  uint32_t rttSampleUs = 0;
  bool haveRtt = false;
  uint32_t freed = 0;
  while (!sendQueue_.empty()) {
    auto& front = sendQueue_.front();
    if (!seqLeq(front.seq, ackNr)) {
      break;
    }
    if (!haveRtt && front.retransmits == 0) {
      // RTT only from packets sent exactly once (spec).
      rttSampleUs = nowUs - front.sendTimeUs;
      haveRtt = true;
    }
    freed += front.size;
    if (front.seq == finSeq_ && finSent_) {
      finAcked_ = true;
    }
    sendQueue_.pop_front();
  }
  if (freed > 0) {
    curWindow_ -= freed;
    if (haveRtt) {
      updateRtt(rttSampleUs);
    }
    updateWindow(nowUs, freed);
    wantWrite_ = true; // window freed; try flushing in processTick
  }
  // FIN 不进入 sendQueue_（由 queueControl 直发），其确认只能通过
  // 累计 ack_nr 判定——否则 finAcked_ 永不置位，优雅关闭退化为双向
  // 超时。
  if (finSent_ && !finAcked_ && seqLeq(finSeq_, ackNr)) {
    finAcked_ = true;
  }

  // Fast retransmit: oldest unacked + >= 3 SACK'd packets after it.
  if (!sendQueue_.empty()) {
    uint16_t oldest = sendQueue_.front().seq;
    bool oldestUnacked = seqAfter(oldest, ackNr);
    unsigned sacksAfter = 0;
    for (unsigned bit = 0; bit < 32; ++bit) {
      if (sackBits & (1u << bit)) {
        uint16_t s = static_cast<uint16_t>(ackNr + 2 + bit);
        if (seqAfter(s, oldest)) {
          ++sacksAfter;
        }
      }
    }
    if (oldestUnacked && sacksAfter >= 3 &&
        !(fastRecoveryValid_ && lastFastRecoverySeq_ == oldest)) {
      // Retransmit the oldest packet and halve the cwnd (per spec).
      // 同一个丢失包只减半一次——连续 SACK 会在几个 ACK 内把 cwnd
      // 打到下限。
      retransmitPacket(sendQueue_.front(), nowUs);
      maxWindow_ = std::max<uint32_t>(maxWindow_ / 2, packetSize_);
      lastFastRecoverySeq_ = oldest;
      fastRecoveryValid_ = true;
    }
  }
  // 3 duplicate acks on ack_nr+1 -> fast retransmit that packet.
  if (dupAckCount_ >= 3) {
    uint16_t target = static_cast<uint16_t>(ackNr + 1);
    for (auto& p : sendQueue_) {
      if (p.seq == target) {
        if (!(fastRecoveryValid_ && lastFastRecoverySeq_ == target)) {
          retransmitPacket(p, nowUs);
          maxWindow_ = std::max<uint32_t>(maxWindow_ / 2, packetSize_);
          lastFastRecoverySeq_ = target;
          fastRecoveryValid_ = true;
        }
        break;
      }
    }
    dupAckCount_ = 0;
  }
  if (finSent_ && finAcked_) {
    finishCloseIfIdle();
  }
}

// ---------------------------------------------------------------------------
// Timers / CC
// ---------------------------------------------------------------------------

void UtpConnection::processTick(uint32_t nowUs)
{
  if (state_ == State::CLOSED) {
    return;
  }

  // Flush a requested FIN.
  if (finPending_) {
    finPending_ = false;
    finSent_ = true;
    finSeq_ = nextSeq();
    seq_ = finSeq_;
    if (state_ == State::SYN_SENT) {
      state_ = State::CLOSED;
    }
    else {
      state_ = State::FIN_SENT;
    }
    // 第三个参数传 0：queueControl 会用 ack_ 填 ack_nr。传 finSeq_
    // 会把我方 FIN 的序号写进 ack_nr，对端会误读为"自己的包已被
    // 累计确认"。
    queueControl(ST_FIN, nowUs, 0);
    if (state_ == State::CLOSED) {
      return;
    }
  }

  // RTO / handshake timeout.
  // BEP 29：RTO 只用于重传未确认数据（或握手/FIN 未完成）。已建立且
  // 无在途数据的空闲连接永远不应因静默被判死——uTP 没有 keepalive，
  // 空闲是常态（对端 choke 我们、本地暂不缺块等）。此前任何静默都会
  // 累计超时，导致空闲约 1.5×RTO 后连接被强杀。
  const bool finInFlight =
      finSent_ && !finAcked_ && state_ == State::FIN_SENT;
  const bool needRto = state_ == State::SYN_SENT ||
                       (lastRecvUs_ != 0 &&
                        (!sendQueue_.empty() || finInFlight));
  if (needRto) {
    uint32_t sinceLast = state_ == State::SYN_SENT
                             ? (nowUs - lastSendUs_)
                             : (nowUs - lastRecvUs_);
    if (sinceLast > timeout_) {
      handleTimeout(nowUs);
      return;
    }
  }

  // Flush pending user data subject to the CC + flow windows. Data
  // packets may only be sent once the connection is established (the
  // peer can otherwise not ack them).
  if (state_ == State::CONNECTED || state_ == State::FIN_SENT) {
    while (!pendingSend_.empty()) {
      if (!canSendData()) {
        wantWrite_ = true;
        break;
      }
      size_t chunk = std::min<size_t>(pendingSend_.size(), packetSize_);
      OutPacket op;
      op.payload.assign(pendingSend_.begin(), pendingSend_.begin() + chunk);
      op.seq = nextSeq();
      seq_ = op.seq;
      op.sendTimeUs = nowUs;
      op.size = static_cast<uint32_t>(chunk);
      pendingSend_.erase(pendingSend_.begin(), pendingSend_.begin() + chunk);
      queueDataPacket(std::move(op), nowUs);
    }
  }

  // Flush pending ACKs (pure ST_STATE).
  if (ackPending_) {
    sendAck(nowUs);
  }

  // Deliverability state for the transport.
  wantRead_ = wantRead_ || !recvOut_.empty() || eofReceived();
}

void UtpConnection::handleTimeout(uint32_t nowUs)
{
  if (state_ == State::SYN_SENT) {
    // 自定义 SYN 总预算（未知 uTP 能力 peer 的快速探测）：到点直接
    // 失败，让上层尽快回退 TCP，而不是吃满默认 ~7.5s 重试预算。
    if (synDeadlineValid_ &&
        static_cast<int32_t>(nowUs - synDeadlineUs_) >= 0) {
      error_ = true;
      state_ = State::CLOSED;
      return;
    }
    // Retransmit the SYN a few times before giving up.
    ++synAttempts_;
    timeout_ = std::min<uint32_t>(timeout_ * 2, RTO_MAX_US);
    if (synAttempts_ >= 4) {
      error_ = true;
      state_ = State::CLOSED;
      return;
    }
    queueControl(ST_SYN, nowUs, 0);
    lastSendUs_ = nowUs;
    return;
  }

  ++consecutiveTimeouts_;
  timeout_ = std::min<uint32_t>(timeout_ * 2, RTO_MAX_US);
  if (consecutiveTimeouts_ >= 2) {
    // No response for two RTOs — the connection is dead. Let the caller
    // drop the peer.
    error_ = true;
    state_ = State::CLOSED;
    return;
  }
  // Spec: collapse to a single minimum packet and retransmit everything.
  packetSize_ = MIN_PACKET_SIZE;
  maxWindow_ = packetSize_;
  lastRecvUs_ = nowUs; // arm the next timeout period
  retransmitUnacked(nowUs);
  // FIN 不在 sendQueue_ 中，retransmitUnacked 不会重发它——FIN 丢失
  // 时必须在 RTO 路径单独重传，否则优雅关闭卡死在 FIN_SENT。
  if (finSent_ && !finAcked_ && state_ == State::FIN_SENT) {
    queueControl(ST_FIN, nowUs, 0);
  }
}

void UtpConnection::retransmitPacket(OutPacket& p, uint32_t nowUs)
{
  p.sendTimeUs = nowUs;
  ++p.retransmits;
  std::vector<unsigned char> pkt(HEADER_LEN + p.payload.size());
  PacketHeader h;
  h.type = ST_DATA;
  h.connectionId = sendId_;
  h.timestamp = nowUs;
  h.timestampDiff = tsDiffEcho_;
  h.wndSize = advertsiedWnd();
  h.seqNr = p.seq;
  h.ackNr = ack_;
  encodeHeader(pkt.data(), h);
  std::copy(p.payload.begin(), p.payload.end(), pkt.begin() + HEADER_LEN);
  outbox_.push_back(std::move(pkt));
  replyMicro_ = nowUs;
  lastSendUs_ = nowUs;
}

void UtpConnection::retransmitUnacked(uint32_t nowUs)
{
  for (auto& p : sendQueue_) {
    p.sendTimeUs = nowUs;
    ++p.retransmits;
    std::vector<unsigned char> pkt(HEADER_LEN + p.payload.size());
    PacketHeader h;
    h.type = ST_DATA;
    h.connectionId = sendId_;
    h.timestamp = nowUs;
    h.timestampDiff = tsDiffEcho_;
    h.wndSize = advertsiedWnd();
    h.seqNr = p.seq;
    h.ackNr = ack_;
    encodeHeader(pkt.data(), h);
    std::copy(p.payload.begin(), p.payload.end(), pkt.begin() + HEADER_LEN);
    outbox_.push_back(std::move(pkt));
  }
}

void UtpConnection::updateRtt(uint32_t packetRttUs)
{
  if (packetRttUs == 0 || packetRttUs > RTO_MAX_US) {
    return;
  }
  if (rtt_ == 0) {
    rtt_ = packetRttUs;
    rttVar_ = packetRttUs / 2;
  }
  else {
    int64_t delta = static_cast<int64_t>(rtt_) - packetRttUs;
    int64_t absDelta = delta < 0 ? -delta : delta;
    rttVar_ = static_cast<uint32_t>(rttVar_ + ((absDelta - rttVar_) / 4));
    // 必须用有符号运算：样本小于均值时无符号减法会下溢到 ~2^32，
    // 使 rtt_ 暴涨至数分钟量级（RFC 6298 的 EWMA 语义）。
    rtt_ = static_cast<uint32_t>(static_cast<int64_t>(rtt_) +
                                 ((static_cast<int64_t>(packetRttUs) -
                                   static_cast<int64_t>(rtt_)) /
                                  8));
  }
  // RTO 需要上下限：下限防止过于激进的重传，上限防止异常样本把
  // 丢包恢复停滞数分钟。
  timeout_ = std::min<uint32_t>(
      std::max<uint32_t>(rtt_ + 4 * rttVar_, RTO_MIN_US), RTO_MAX_US);
}

void UtpConnection::updateDelay(uint32_t sampleUs, uint32_t nowUs)
{
  lastDelaySampleUs_ = sampleUs;
  if (baseDelay_ == 0 || sampleUs < baseDelay_ ||
      nowUs - baseDelaySetUs_ > BASE_DELAY_WINDOW_US) {
    baseDelay_ = sampleUs;
    baseDelaySetUs_ = nowUs;
  }
}

void UtpConnection::updateWindow(uint32_t nowUs, uint32_t newlyAcked)
{
  // LEDBAT: off_target = target - our_delay.
  uint32_t ourDelay = baseDelay_ == 0 || lastDelaySampleUs_ <= baseDelay_
                          ? 0
                          : lastDelaySampleUs_ - baseDelay_;
  int64_t offTarget = static_cast<int64_t>(CC_TARGET_US) - ourDelay;
  double delayFactor = static_cast<double>(offTarget) / CC_TARGET_US;
  if (delayFactor < 0) {
    delayFactor = 0; // over target: don't grow (loss path shrinks instead)
  }
  // libutp/LEDBAT 语义：窗口增长按"本次新确认的字节数"等比缩放，
  // 而非每个 ACK 固定 +1 MSS。延迟远低于目标时（如冷启动无基线）
  // 增长近似指数（等效 slow start），逼近目标后自动收敛到线性。
  // 丢包路径（超时/快速重传）仍减半兜底。
  int64_t delta = static_cast<int64_t>(MAX_CWND_INCREASE_PER_RTT *
                                       delayFactor * newlyAcked);
  // Startup boost while we have no delay baseline yet (slow start).
  if (baseDelay_ == 0) {
    delta += packetSize_;
  }
  int64_t newWindow = static_cast<int64_t>(maxWindow_) + delta;
  maxWindow_ = static_cast<uint32_t>(
      std::max<int64_t>(newWindow, packetSize_));
}

bool UtpConnection::canSendData() const
{
  // Spec: cur_window + packet_size <= min(max_window, wnd_size).
  uint32_t cap = std::min(maxWindow_, peerWnd_);
  return curWindow_ + packetSize_ <= cap;
}

uint32_t UtpConnection::advertsiedWnd() const
{
  uint32_t used = recvBuffered_ + static_cast<uint32_t>(recvOut_.size());
  return used >= RECV_WINDOW ? 0 : RECV_WINDOW - used;
}

void UtpConnection::queueDataPacket(OutPacket&& op, uint32_t nowUs)
{
  curWindow_ += op.size;
  std::vector<unsigned char> pkt(HEADER_LEN + op.payload.size());
  PacketHeader h;
  h.type = ST_DATA;
  h.connectionId = sendId_;
  h.timestamp = nowUs;
  h.timestampDiff = tsDiffEcho_;
  h.wndSize = advertsiedWnd();
  h.seqNr = op.seq;
  h.ackNr = ack_;
  encodeHeader(pkt.data(), h);
  std::copy(op.payload.begin(), op.payload.end(), pkt.begin() + HEADER_LEN);
  outbox_.push_back(std::move(pkt));
  replyMicro_ = nowUs;
  lastSendUs_ = nowUs;
  sendQueue_.push_back(std::move(op));
}

void UtpConnection::sendAck(uint32_t nowUs)
{
  queueControl(ST_STATE, nowUs, ack_);
  ackPending_ = false;
}

void UtpConnection::queueControl(uint8_t type, uint32_t nowUs,
                                 uint16_t seqForAck)
{
  // BEP 29：connection_id 对每个端点是常量——我方所有出站包（SYN、
  // ST_STATE、ST_DATA、ST_FIN）一律携带 sendId_。
  uint16_t connId = sendId_;
  uint16_t seqField = (type == ST_FIN) ? finSeq_ : seq_;
  // Build with optional SACK extension when we have gaps.
  bool haveGaps = !recvReorder_.empty();
  size_t total = HEADER_LEN + (haveGaps ? 6 : 0);
  std::vector<unsigned char> pkt(total);
  PacketHeader h;
  h.type = type;
  h.connectionId = connId;
  h.timestamp = nowUs;
  h.timestampDiff = tsDiffEcho_;
  h.wndSize = advertsiedWnd();
  h.seqNr = seqField;
  h.ackNr = seqForAck == 0 ? ack_ : seqForAck;
  if (haveGaps) {
    h.extension = EXT_SACK;
  }
  encodeHeader(pkt.data(), h);
  if (haveGaps) {
    // SACK bits: acked packets in the reorder buffer (relative to ack_).
    uint32_t bits = 0;
    for (const auto& kv : recvReorder_) {
      int32_t off = static_cast<int32_t>(kv.first) - ack_ - 2;
      if (off >= 0 && off < 32) {
        bits |= (1u << off);
      }
    }
    size_t off = HEADER_LEN;
    appendSackExtension(pkt.data(), off, bits);
  }
  outbox_.push_back(std::move(pkt));
  replyMicro_ = nowUs;
  lastSendUs_ = nowUs;
}

void UtpConnection::finishCloseIfIdle()
{
  if (finSent_ && finAcked_ && eofReceived()) {
    state_ = State::CLOSED;
  }
}

void UtpConnection::close()
{
  if (finPending_ || finSent_ || state_ == State::CLOSED) {
    return;
  }
  if (state_ == State::SYN_SENT) {
    state_ = State::CLOSED; // never connected; nothing to shut down
    return;
  }
  // FIN is queued and flushed on the next processTick() with a proper
  // timestamp (queueControl needs nowUs).
  finPending_ = true;
}

void UtpConnection::drainOutbox(std::vector<std::vector<unsigned char>>& out)
{
  if (outbox_.empty()) {
    return;
  }
  out.insert(out.end(), std::make_move_iterator(outbox_.begin()),
             std::make_move_iterator(outbox_.end()));
  outbox_.clear();
}

} // namespace utp
} // namespace aria2
