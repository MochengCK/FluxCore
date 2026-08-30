#include "MSEHandshake.h"

#include <cstring>
#include <functional>

#include <cppunit/extensions/HelperMacros.h>

#include "Exception.h"
#include "util.h"
#include "prefs.h"
#include "SocketLike.h"
#include "UtpSocketLike.h"
#include "UtpConnection.h"
#include "UtpPacket.h"
#include "ARC4Encryptor.h"
#include "Option.h"
#include "DownloadContext.h"
#include "FileEntry.h"
#include "array_fun.h"
#include "bittorrent_helper.h"

namespace aria2 {

// MSE/PE 握手在 uTP（BEP 29）传输上的端到端验证：两个内存直连的
// UtpConnection 互相泵包，双方 MSEHandshake 完成 DH 协商并验证
// ARC4 密钥真实可解密。对应引擎中 Initiator/ReceiverMSEHandshakeCommand
// 的 uTP 模式（UtpSocketLike 传输）。
class MSEHandshakeUtpTest : public CppUnit::TestFixture {

  CPPUNIT_TEST_SUITE(MSEHandshakeUtpTest);
  CPPUNIT_TEST(testHandshakeOverUtp);
  CPPUNIT_TEST_SUITE_END();

private:
  std::shared_ptr<DownloadContext> dctx_;

public:
  void setUp()
  {
    dctx_.reset(new DownloadContext());
    unsigned char infoHash[20];
    memset(infoHash, 0, sizeof(infoHash));
    {
      auto torrentAttrs = make_unique<TorrentAttribute>();
      torrentAttrs->infoHash.assign(std::begin(infoHash), std::end(infoHash));
      dctx_->setAttribute(CTX_ATTR_BT, std::move(torrentAttrs));
    }
  }

  void testHandshakeOverUtp();
};

CPPUNIT_TEST_SUITE_REGISTRATION(MSEHandshakeUtpTest);

namespace {

// 两个 UtpConnection 内存直连：互相搬运数据包并推进各自定时器。
struct UtpWire {
  utp::UtpConnection& a;
  utp::UtpConnection& b;
  uint32_t now = 1000;

  void pump(int rounds = 1)
  {
    for (int i = 0; i < rounds; ++i) {
      a.processTick(now);
      b.processTick(now);
      std::vector<std::vector<unsigned char>> out;
      a.drainOutbox(out);
      for (auto& p : out) {
        b.handlePacket(p.data(), p.size(), now);
      }
      out.clear();
      b.drainOutbox(out);
      for (auto& p : out) {
        a.handlePacket(p.data(), p.size(), now);
      }
      now += 1000;
    }
  }
};

} // namespace

void MSEHandshakeUtpTest::testHandshakeOverUtp()
{
  Option op;
  op.put(PREF_BT_MIN_CRYPTO_LEVEL, V_ARC4);

  uint32_t now = 1000;
  // 发起方：构造即入队 SYN（与 UtpContext::connect 一致）
  auto initiatorConn =
      std::make_shared<utp::UtpConnection>("127.0.0.1", 1, now, 0);
  initiatorConn->processTick(now);
  std::vector<std::vector<unsigned char>> out;
  initiatorConn->drainOutbox(out);
  CPPUNIT_ASSERT(!out.empty());
  utp::PacketHeader synHdr;
  std::vector<std::pair<uint8_t, std::vector<uint8_t>>> exts;
  CPPUNIT_ASSERT(
      utp::parsePacket(out[0].data(), out[0].size(), synHdr, exts));
  CPPUNIT_ASSERT_EQUAL(static_cast<int>(utp::ST_SYN),
                       static_cast<int>(synHdr.type));

  // 响应方：按 SYN 建连（与 UtpContext::receiveLoop 的 accept 路径一致）
  auto receiverConn = std::make_shared<utp::UtpConnection>(
      "127.0.0.1", 1, synHdr.connectionId, synHdr.seqNr, now);
  receiverConn->handlePacket(out[0].data(), out[0].size(), now);

  UtpWire wire{*initiatorConn, *receiverConn};
  for (int i = 0; i < 50 && !initiatorConn->isConnected(); ++i) {
    wire.pump(1);
  }
  CPPUNIT_ASSERT(initiatorConn->isConnected());

  auto initiator = std::make_shared<MSEHandshake>(
      1, std::make_shared<UtpSocketLike>(initiatorConn), &op);
  auto receiver = std::make_shared<MSEHandshake>(
      2, std::make_shared<UtpSocketLike>(receiverConn), &op);
  initiator->initEncryptionFacility(true);
  receiver->initEncryptionFacility(false);

  // uTP 上 read()/send() 非阻塞：所有"读到足够数据"都要先泵包。
  auto readUntil = [&](MSEHandshake& h, const std::function<bool()>& done) {
    for (int i = 0; i < 500; ++i) {
      wire.pump(1);
      h.read();
      if (done()) {
        return true;
      }
    }
    return false;
  };
  auto flush = [&](MSEHandshake& h) {
    for (int i = 0; i < 500 && h.getWantWrite(); ++i) {
      wire.pump(1);
      h.send();
    }
  };

  // 与 MSEHandshakeTest::doHandshake 相同的消息序列
  initiator->sendPublicKey();
  flush(*initiator);
  CPPUNIT_ASSERT(
      readUntil(*receiver, [&] { return receiver->receivePublicKey(); }));
  receiver->sendPublicKey();
  flush(*receiver);
  CPPUNIT_ASSERT(
      readUntil(*initiator, [&] { return initiator->receivePublicKey(); }));
  initiator->initCipher(bittorrent::getInfoHash(dctx_));
  initiator->sendInitiatorStep2();
  flush(*initiator);
  CPPUNIT_ASSERT(readUntil(*receiver,
                           [&] { return receiver->findReceiverHashMarker(); }));
  std::vector<std::shared_ptr<DownloadContext>> contexts;
  contexts.push_back(dctx_);
  CPPUNIT_ASSERT(readUntil(*receiver, [&] {
    return receiver->receiveReceiverHashAndPadCLength(contexts);
  }));
  CPPUNIT_ASSERT(readUntil(*receiver, [&] { return receiver->receivePad(); }));
  CPPUNIT_ASSERT(
      readUntil(*receiver, [&] { return receiver->receiveReceiverIALength(); }));
  CPPUNIT_ASSERT(
      readUntil(*receiver, [&] { return receiver->receiveReceiverIA(); }));
  receiver->sendReceiverStep2();
  flush(*receiver);
  CPPUNIT_ASSERT(readUntil(*initiator,
                           [&] { return initiator->findInitiatorVCMarker(); }));
  CPPUNIT_ASSERT(readUntil(*initiator, [&] {
    return initiator->receiveInitiatorCryptoSelectAndPadDLength();
  }));
  CPPUNIT_ASSERT(readUntil(*initiator, [&] { return initiator->receivePad(); }));

  CPPUNIT_ASSERT_EQUAL(MSEHandshake::CRYPTO_ARC4,
                       initiator->getNegotiatedCryptoType());
  CPPUNIT_ASSERT_EQUAL(MSEHandshake::CRYPTO_ARC4,
                       receiver->getNegotiatedCryptoType());

  // 协商出的密钥真实可用：发起方加密 -> 接收方同密钥流解密还原。
  auto enc = initiator->popEncryptor();
  auto dec = receiver->popDecryptor();
  CPPUNIT_ASSERT(enc.get());
  CPPUNIT_ASSERT(dec.get());
  const std::string plain = "uTP MSE payload roundtrip";
  std::vector<unsigned char> buf(plain.begin(), plain.end());
  enc->encrypt(buf.size(), buf.data(), buf.data());
  CPPUNIT_ASSERT(memcmp(buf.data(), plain.data(), plain.size()) != 0);
  dec->encrypt(buf.size(), buf.data(), buf.data());
  CPPUNIT_ASSERT_EQUAL(plain, std::string(buf.begin(), buf.end()));
}

} // namespace aria2
