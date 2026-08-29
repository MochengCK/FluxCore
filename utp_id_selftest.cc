// uTP connection_id 方案自测（BEP 29 / libtorrent 兼容性）。
// 不依赖引擎其余部分，直接编译 UtpPacket + UtpConnection，模拟
// 发起方/响应方两个连接互发握手与数据，断言：
//   - SYN 携带发起方 recv_id、wnd_size=0，send_id = recv_id + 1
//   - 响应方 send_id = SYN.conn_id、recv_id = send_id + 1
//   - 发起方数据包携带 send_id（= 响应方 recv_id），双向数据可达
// 编译运行（在 XferCore/ 目录下）：
//   c++ -std=c++17 -Isrc -Ideps -Ilib -DENABLE_BITTORRENT \
//       -o /tmp/utp_selftest utp_id_selftest.cc src/UtpPacket.cc \
//       src/UtpConnection.cc && /tmp/utp_selftest
#include <cassert>
#include <cstdio>
#include <cstring>
#include <vector>
#include "UtpPacket.h"
#include "UtpConnection.h"

using namespace aria2;
using namespace aria2::utp;

static std::vector<std::vector<unsigned char>> drain(UtpConnection& c) {
  std::vector<std::vector<unsigned char>> out;
  c.drainOutbox(out);
  return out;
}

static bool parse(const std::vector<unsigned char>& p, PacketHeader& h) {
  std::vector<std::pair<uint8_t, std::vector<uint8_t>>> exts;
  return parsePacket(p.data(), p.size(), h, exts);
}

int main() {
  uint32_t now = 1000000;
  // A: initiator
  UtpConnection A("1.2.3.4", 6881, now, 0);
  auto synPkts = drain(A);
  assert(synPkts.size() == 1);
  PacketHeader syn;
  assert(parse(synPkts[0], syn));
  assert(syn.type == ST_SYN);
  assert(syn.version == 1);
  printf("SYN: conn_id=%u seq=%u ack=%u wnd=%u (A.recvId=%u A.sendId=%u)\n",
         syn.connectionId, syn.seqNr, syn.ackNr, syn.wndSize,
         A.getRecvId(), A.getSendId());
  // BEP29/libtorrent: SYN carries initiator's recv_id; send_id = recv_id+1
  assert(syn.connectionId == A.getRecvId());
  assert(A.getSendId() == (uint16_t)(A.getRecvId() + 1));
  assert(syn.wndSize == 0); // libtorrent send_syn: wnd 0

  // B: responder receives SYN
  UtpConnection B("5.6.7.8", 55555, syn.connectionId, syn.seqNr, now + 1000);
  printf("B: sendId=%u recvId=%u\n", B.getSendId(), B.getRecvId());
  // libtorrent responder: send_id = SYN.conn_id, recv_id = send_id+1
  assert(B.getSendId() == syn.connectionId);
  assert(B.getRecvId() == (uint16_t)(B.getSendId() + 1));

  auto ackPkts = drain(B);
  assert(ackPkts.size() == 1);
  PacketHeader synack;
  assert(parse(ackPkts[0], synack));
  assert(synack.type == ST_STATE);
  printf("SYN-ACK: conn_id=%u seq=%u ack=%u\n", synack.connectionId, synack.seqNr, synack.ackNr);
  // Responder replies with SYN.conn_id; acks the SYN seq
  assert(synack.connectionId == syn.connectionId);
  assert(synack.ackNr == syn.seqNr);

  // A receives SYN-ACK -> CONNECTED (routed by A.recvId)
  assert(synack.connectionId == A.getRecvId());
  A.handlePacket(ackPkts[0].data(), ackPkts[0].size(), now + 2000);
  assert(A.isConnected());
  printf("A connected after SYN-ACK\n");

  // A sends BT handshake as data
  const char* hs = "BitTorrent protocol\x13";
  size_t hsLen = strlen(hs);
  assert(A.write((const unsigned char*)hs, hsLen) == hsLen);
  A.processTick(now + 3000);
  auto dataPkts = drain(A);
  assert(dataPkts.size() == 1);
  PacketHeader d1;
  assert(parse(dataPkts[0], d1));
  assert(d1.type == ST_DATA);
  printf("DATA(A->B): conn_id=%u seq=%u (expect SYN.conn_id+1=%u)\n",
         d1.connectionId, d1.seqNr, (uint16_t)(syn.connectionId + 1));
  // Initiator data carries send_id = recv_id+1 = SYN.conn_id + 1 = B.recvId
  assert(d1.connectionId == A.getSendId());
  assert(d1.connectionId == B.getRecvId());

  // B receives it
  B.handlePacket(dataPkts[0].data(), dataPkts[0].size(), now + 4000);
  assert(B.isConnected());
  unsigned char rbuf[256];
  size_t got = B.read(rbuf, sizeof(rbuf));
  assert(got == hsLen && memcmp(rbuf, hs, hsLen) == 0);
  printf("B received handshake (%zu bytes)\n", got);

  // B replies with data carrying B.sendId == SYN.conn_id == A.recvId
  const char* resp = "handshake-back";
  size_t rLen = strlen(resp);
  assert(B.write((const unsigned char*)resp, rLen) == rLen);
  B.processTick(now + 5000);
  // B may queue an ACK first; drain all
  auto bPkts = drain(B);
  assert(!bPkts.empty());
  bool gotResp = false;
  for (auto& p : bPkts) {
    PacketHeader h;
    assert(parse(p, h));
    assert(h.connectionId == B.getSendId());
    assert(h.connectionId == A.getRecvId());
    assert(h.connectionId == syn.connectionId);
    if (h.type == ST_DATA) {
      A.handlePacket(p.data(), p.size(), now + 6000);
      gotResp = true;
    } else {
      A.handlePacket(p.data(), p.size(), now + 6000);
    }
  }
  assert(gotResp);
  unsigned char abuf[256];
  size_t agot = A.read(abuf, sizeof(abuf));
  assert(agot == rLen && memcmp(abuf, resp, rLen) == 0);
  printf("A received reply (%zu bytes)\n", agot);

  printf("ALL UTP PROTOCOL CHECKS PASSED\n");
  return 0;
}
