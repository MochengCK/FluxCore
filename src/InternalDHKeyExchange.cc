/* <!-- copyright */
/*
 * aria2 - The high speed download utility
 *
 * Copyright (C) 2013 Nils Maier
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

#include "InternalDHKeyExchange.h"

#include <algorithm>
#include <cstring>
#include <vector>

#include "DlAbortEx.h"
#include "LogFactory.h"
#include "fmt.h"
#include "util.h"

namespace aria2 {

namespace {
// bignum（ulong<dim>）内部是小端字节序（buf[0] 为最低位字节），而
// MSE (BEP 8) 的线上格式是固定 96 字节大端：素数 hex 串经 fromHex
// 得到的是大端字节，对端公钥/我方公钥/共享密钥 S 也都以大端在
// 线上传输并参与 SHA1。此前边界处未做字节序转换——素数被当成另一
// 个数、公钥/密钥字节全部颠倒——引擎自连（两侧同错）能通，但与
// 任何规范实现（qBittorrent/libtorrent，大端）共享密钥必然不一致，
// MSE 握手 VC 校验永远失败，表现为"零加密连接"。
void reverseBytes(const unsigned char* in, size_t len, unsigned char* out)
{
  for (size_t i = 0; i < len; ++i) {
    out[i] = in[len - 1 - i];
  }
}
} // namespace

void DHKeyExchange::init(const unsigned char* prime, size_t primeBits,
                         const unsigned char* generator, size_t privateKeyBits)
{
  std::string pr = reinterpret_cast<const char*>(prime);
  if (pr.length() % 2) {
    pr = "0" + pr;
  }
  pr = util::fromHex(pr.begin(), pr.end());
  if (pr.empty()) {
    throw DL_ABORT_EX("No valid prime supplied");
  }
  {
    // 大端 → 小端（bignum 内部表示）
    std::vector<unsigned char> tmp(pr.begin(), pr.end());
    std::reverse(tmp.begin(), tmp.end());
    prime_ = n(tmp.data(), tmp.size());
  }

  std::string gen = reinterpret_cast<const char*>(generator);
  if (gen.length() % 2) {
    gen = "0" + gen;
  }
  gen = util::fromHex(gen.begin(), gen.end());
  if (gen.empty()) {
    throw DL_ABORT_EX("No valid generator supplied");
  }
  {
    std::vector<unsigned char> tmp(gen.begin(), gen.end());
    std::reverse(tmp.begin(), tmp.end());
    generator_ = n(tmp.data(), tmp.size());
  }

  size_t pbytes = (privateKeyBits + 7) / 8;
  unsigned char buf[pbytes];
  util::generateRandomData(buf, pbytes);
  privateKey_ = n(buf, pbytes);

  keyLength_ = (primeBits + 7) / 8;
}

void DHKeyExchange::generatePublicKey()
{
  // DH 公钥必须是幂模 g^x mod p。此前误用 mul_mod（g*x mod p），
  // 双方共享密钥永远无法一致，MSE 加密握手必然失败。
  publicKey_ = generator_.pow_mod(privateKey_, prime_);
}

size_t DHKeyExchange::getPublicKey(unsigned char* out, size_t outLength) const
{
  if (outLength < keyLength_) {
    throw DL_ABORT_EX(
        fmt("Insufficient buffer for public key. expect:%lu, actual:%lu",
            static_cast<unsigned long>(keyLength_),
            static_cast<unsigned long>(outLength)));
  }
  {
    std::vector<unsigned char> tmp(keyLength_);
    publicKey_.binary(tmp.data(), keyLength_);
    // 小端内部 → 大端线上
    reverseBytes(tmp.data(), keyLength_, out);
  }
  return keyLength_;
}

void DHKeyExchange::generateNonce(unsigned char* out, size_t outLength) const
{
  util::generateRandomData(out, outLength);
}

size_t DHKeyExchange::computeSecret(unsigned char* out, size_t outLength,
                                    const unsigned char* peerPublicKeyData,
                                    size_t peerPublicKeyLength) const
{
  if (outLength < keyLength_) {
    throw DL_ABORT_EX(
        fmt("Insufficient buffer for secret. expect:%lu, actual:%lu",
            static_cast<unsigned long>(keyLength_),
            static_cast<unsigned long>(outLength)));
  }
  if (prime_.length() < peerPublicKeyLength) {
    throw DL_ABORT_EX(
        fmt("peer public key overflows bignum. max:%lu, actual:%lu",
            static_cast<unsigned long>(prime_.length()),
            static_cast<unsigned long>(peerPublicKeyLength)));
  }

  // 对端公钥：大端线上 → 小端内部
  std::vector<unsigned char> peerTmp(peerPublicKeyLength);
  reverseBytes(peerPublicKeyData, peerPublicKeyLength, peerTmp.data());
  n peerKey(peerTmp.data(), peerTmp.size());
  // 共享密钥 = 对端公钥^私钥 mod p（幂模）。见 generatePublicKey 注释。
  n secret = peerKey.pow_mod(privateKey_, prime_);
  {
    std::vector<unsigned char> tmp(keyLength_);
    secret.binary(tmp.data(), keyLength_);
    // 小端内部 → 大端线上（SHA1 输入要求）
    reverseBytes(tmp.data(), keyLength_, out);
  }

  return outLength;
}

} // namespace aria2
