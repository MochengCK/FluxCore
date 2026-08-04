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
#ifndef D_UTP_CONNECTION_H
#define D_UTP_CONNECTION_H

#include "common.h"
#include "UtpPacket.h"

#include <cstdint>
#include <deque>
#include <map>
#include <string>
#include <vector>

namespace aria2 {
namespace utp {

// A single uTP connection (BEP 29, self-implemented).
//
// Design goals — correctness against the spec, and performance:
//  - Tick-driven: everything happens in processTick()/handlePacket()
//    called from the engine event loop; no threads, no blocking.
//  - Bounded memory: the send pipeline is capped by the congestion +
//    flow windows, the receive side by the advertised window.
//  - LEDBAT delay-based congestion control (100ms target) with a 2min
//    sliding-minimum base delay, additive increase / multiplicative
//    decrease (x0.5 on loss), so the link is never saturated with
//    queueing delay.
//  - Selective ACK + fast retransmit + RTO (RFC 6298-style EWMA,
//    500ms floor, doubling on consecutive timeouts).
//
// The connection does NOT own a socket: it produces encoded outgoing
// datagrams into an outbox that UtpContext flushes over the shared UDP
// socket, and consumes incoming datagrams via handlePacket().

class UtpConnection {
public:
  enum class State { SYN_SENT, SYN_RECV, CONNECTED, FIN_SENT, CLOSED };

  // Create an outbound (initiator) connection. The SYN is queued on
  // construction and flushed by processTick().
  UtpConnection(const std::string& remoteAddr, uint16_t remotePort,
                uint32_t nowUs);

  // Create an inbound (responder) connection after receiving a SYN.
  // peerRecvId is the connection_id from the SYN packet; ackNr is the
  // SYN's sequence number.
  UtpConnection(const std::string& remoteAddr, uint16_t remotePort,
                uint16_t peerRecvId, uint16_t ackNr, uint32_t nowUs);

  ~UtpConnection();

  // --- User-facing stream API (used by the transport adapter) ---

  // Buffer up to len bytes for sending. Returns bytes accepted.
  size_t write(const unsigned char* data, size_t len);

  // Read received in-order bytes. On EAGAIN sets wantRead_ and returns
  // 0; on EOF returns 0 with eof_ set.
  size_t read(unsigned char* data, size_t cap);

  bool wantRead() const { return wantRead_; }
  bool wantWrite() const { return wantWrite_; }
  // True once the connection is usable for the peer protocol.
  bool isConnected() const { return state_ >= State::CONNECTED; }
  // True when the peer closed and all its data was delivered.
  bool eofReceived() const { return eof_ && recvOut_.empty() &&
                                    recvReorder_.empty(); }
  bool isClosed() const { return state_ == State::CLOSED; }
  // Set on protocol errors / RESET.
  bool hasError() const { return error_; }

  // --- Protocol machinery (driven by UtpContext) ---

  // Process one incoming datagram (already length-validated).
  void handlePacket(const unsigned char* data, size_t len, uint32_t nowUs);

  // Advance timers / retransmission / congestion control and flush
  // queued packets. Sends are subject to the CC + flow windows.
  void processTick(uint32_t nowUs);

  // Outgoing datagrams produced since the last drain.
  void drainOutbox(std::vector<std::vector<unsigned char>>& out);

  // Graceful close: send FIN after pending data.
  void close();

  const std::string& getRemoteAddr() const { return remoteAddr_; }
  uint16_t getRemotePort() const { return remotePort_; }
  // The connection id to match incoming packets against (our receive id).
  uint16_t getRecvId() const { return recvId_; }

private:
  struct OutPacket {
    std::vector<unsigned char> payload; // data only (no header)
    uint16_t seq = 0;
    uint32_t sendTimeUs = 0;
    uint32_t size = 0;
    unsigned retransmits = 0;
  };

  struct InPacket {
    std::vector<unsigned char> payload;
    uint32_t receivedAtUs = 0;
  };

  // --- helpers ---
  void initCommon(const std::string& remoteAddr, uint16_t remotePort);
  void queueControl(uint8_t type, uint32_t nowUs, uint16_t seqForAck);
  void queueDataPacket(OutPacket&& pkt, uint32_t nowUs);
  void retransmitPacket(OutPacket& p, uint32_t nowUs);
  void sendAck(uint32_t nowUs);
  bool canSendData() const;
  uint16_t nextSeq() const { return static_cast<uint16_t>(seq_ + 1); }

  void onAck(uint16_t ackNr, uint32_t sackBits, uint32_t nowUs);
  void onData(const PacketHeader& hdr, const unsigned char* payload,
              size_t payloadLen, uint32_t nowUs);
  void updateRtt(uint32_t packetRttUs);
  void updateDelay(uint32_t sampleUs, uint32_t nowUs);
  void updateWindow(uint32_t nowUs);
  void retransmitUnacked(uint32_t nowUs);
  void handleTimeout(uint32_t nowUs);
  uint32_t advertsiedWnd() const;
  void finishCloseIfIdle();

  // --- wire identity ---
  std::string remoteAddr_;
  uint16_t remotePort_;
  uint16_t recvId_ = 0; // match incoming
  uint16_t sendId_ = 0; // put in outgoing (post-SYN)

  State state_ = State::SYN_SENT;
  bool error_ = false;

  // --- sequence ---
  uint16_t seq_ = 0; // last seq sent
  uint16_t ack_ = 0; // last contiguous seq received
  bool synAcked_ = false;

  // --- send side ---
  std::deque<unsigned char> pendingSend_; // user data awaiting CC gate
  std::deque<OutPacket> sendQueue_; // unacked packets, in seq order
  uint32_t curWindow_ = 0;          // bytes in flight
  uint32_t maxWindow_ = 0;          // congestion window (bytes)
  uint32_t packetSize_ = 0;         // current payload size
  uint32_t peerWnd_ = 0;            // peer's advertised window
  bool wantWrite_ = false;
  bool ackPending_ = false;         // pure ACK queued (or piggybacked)
  bool finSent_ = false;
  bool finPending_ = false;         // FIN requested by close(), send on tick
  bool finAcked_ = false;
  uint16_t finSeq_ = 0;
  unsigned synAttempts_ = 0;

  // --- receive side ---
  std::deque<unsigned char> recvOut_; // ordered bytes ready to read
  std::map<uint16_t, InPacket> recvReorder_; // out-of-order packets
  uint32_t recvBuffered_ = 0;         // bytes in reorder buffer
  bool eof_ = false;                  // peer FIN received
  uint16_t eofPkt_ = 0;
  bool wantRead_ = false;

  // --- RTT / RTO (µs) ---
  uint32_t rtt_ = 0;
  uint32_t rttVar_ = 0;
  uint32_t timeout_ = 1000 * 1000; // 1s initial (per spec)
  uint32_t lastRecvUs_ = 0;
  uint32_t lastSendUs_ = 0;
  unsigned consecutiveTimeouts_ = 0;

  // --- delay-based CC (LEDBAT) ---
  uint32_t baseDelay_ = 0;     // µs, min over last 2 minutes
  uint32_t baseDelaySetUs_ = 0;
  uint32_t lastDelaySampleUs_ = 0; // latest one-way delay sample from peer
  uint32_t lastAckUs_ = 0;     // for dup-ack detection
  uint16_t lastAckNr_ = 0;
  unsigned dupAckCount_ = 0;

  // --- timestamps echoed from peer ---
  uint32_t lastPeerTs_ = 0;   // timestamp field of last received packet
  uint32_t replyMicro_ = 0;   // ts we put in the last packet we sent

  // --- outbox ---
  std::vector<std::vector<unsigned char>> outbox_;
};

} // namespace utp
} // namespace aria2

#endif // D_UTP_CONNECTION_H
