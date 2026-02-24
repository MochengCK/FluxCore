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
#include "LibsslTLSContext.h"

#include <cassert>
#include <sstream>

#include <openssl/err.h>
#include <openssl/pkcs12.h>
#include <openssl/bio.h>
#include <openssl/x509.h>

#ifdef _WIN32
#  include <windows.h>
#  include <wincrypt.h>
#endif

#include "LogFactory.h"
#include "Logger.h"
#include "fmt.h"
#include "message.h"
#include "BufferedFile.h"

namespace {
struct bio_deleter {
  void operator()(BIO* b)
  {
    if (b)
      BIO_free(b);
  }
};
typedef std::unique_ptr<BIO, bio_deleter> bio_t;
struct p12_deleter {
  void operator()(PKCS12* p)
  {
    if (p)
      PKCS12_free(p);
  }
};
typedef std::unique_ptr<PKCS12, p12_deleter> p12_t;
struct pkey_deleter {
  void operator()(EVP_PKEY* x)
  {
    if (x)
      EVP_PKEY_free(x);
  }
};
typedef std::unique_ptr<EVP_PKEY, pkey_deleter> pkey_t;
struct x509_deleter {
  void operator()(X509* x)
  {
    if (x)
      X509_free(x);
  }
};
typedef std::unique_ptr<X509, x509_deleter> x509_t;
struct x509_sk_deleter {
  void operator()(STACK_OF(X509) * x)
  {
    if (x)
      sk_X509_pop_free(x, X509_free);
  }
};
typedef std::unique_ptr<STACK_OF(X509), x509_sk_deleter> x509_sk_t;

#ifdef _WIN32
bool addWindowsSystemCertStore(SSL_CTX* ctx, const char* storeName,
                               size_t& added)
{
  HCERTSTORE store = CertOpenSystemStoreA(0, storeName);
  if (!store) {
    return false;
  }
  PCCERT_CONTEXT cert = nullptr;
  X509_STORE* x509Store = SSL_CTX_get_cert_store(ctx);
  bool any = false;
  while ((cert = CertEnumCertificatesInStore(store, cert)) != nullptr) {
    const unsigned char* encoded = cert->pbCertEncoded;
    X509* x509 = d2i_X509(nullptr, &encoded, cert->cbCertEncoded);
    if (!x509) {
      continue;
    }
    if (X509_STORE_add_cert(x509Store, x509) == 1) {
      ++added;
      any = true;
    }
    X509_free(x509);
  }
  CertCloseStore(store, 0);
  return any;
}

bool addWindowsSystemCACerts(SSL_CTX* ctx)
{
  size_t added = 0;
  bool okRoot = addWindowsSystemCertStore(ctx, "ROOT", added);
  bool okCa = addWindowsSystemCertStore(ctx, "CA", added);
  return (okRoot || okCa) && added > 0;
}
#endif
} // namespace

namespace aria2 {

TLSContext* TLSContext::make(TLSSessionSide side, TLSVersion minVer)
{
  return new OpenSSLTLSContext(side, minVer);
}

OpenSSLTLSContext::OpenSSLTLSContext(TLSSessionSide side, TLSVersion minVer)
    : sslCtx_(nullptr), side_(side), verifyPeer_(true)
{
  sslCtx_ = SSL_CTX_new(SSLv23_method());
  if (sslCtx_) {
    good_ = true;
  }
  else {
    good_ = false;
    A2_LOG_ERROR(fmt("SSL_CTX_new() failed. Cause: %s",
                     ERR_error_string(ERR_get_error(), nullptr)));
    return;
  }

  long ver_opts = 0;
  switch (minVer) {
#ifdef TLS1_3_VERSION
  case TLS_PROTO_TLS13:
    ver_opts |= SSL_OP_NO_TLSv1_2;
    // fall through
#endif // TLS1_3_VERSION
  case TLS_PROTO_TLS12:
    ver_opts |= SSL_OP_NO_TLSv1_1;
  // fall through
  case TLS_PROTO_TLS11:
    ver_opts |= SSL_OP_NO_TLSv1;
    ver_opts |= SSL_OP_NO_SSLv3;
    break;
  default:
    assert(0);
    abort();
  };

  // Disable SSLv2 and enable all workarounds for buggy servers
  SSL_CTX_set_options(sslCtx_, SSL_OP_ALL | SSL_OP_NO_SSLv2 | ver_opts
#ifdef SSL_OP_SINGLE_ECDH_USE
                                   | SSL_OP_SINGLE_ECDH_USE
#endif // SSL_OP_SINGLE_ECDH_USE
#ifdef SSL_OP_NO_COMPRESSION
                                   | SSL_OP_NO_COMPRESSION
#endif // SSL_OP_NO_COMPRESSION
  );
  
  // 性能优化：启用多种 SSL 模式以提高 HTTPS 下载性能
  SSL_CTX_set_mode(sslCtx_, SSL_MODE_AUTO_RETRY);
  SSL_CTX_set_mode(sslCtx_, SSL_MODE_ENABLE_PARTIAL_WRITE);
  
  // 允许移动写缓冲区，提高写入灵活性
  SSL_CTX_set_mode(sslCtx_, SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER);
  
#ifdef SSL_MODE_RELEASE_BUFFERS
  /* keep memory usage low */
  SSL_CTX_set_mode(sslCtx_, SSL_MODE_RELEASE_BUFFERS);
#endif

  // 设置默认读缓冲区大小以提高性能（OpenSSL 1.1.1+）
  // 16KB 是一个平衡性能和内存的好选择
#if OPENSSL_VERSION_NUMBER >= 0x10101000L
  SSL_CTX_set_default_read_buffer_size(sslCtx_, 16384);
#endif

  if (SSL_CTX_set_cipher_list(sslCtx_, "HIGH:!aNULL:!eNULL") == 0) {
    good_ = false;
    A2_LOG_ERROR(fmt("SSL_CTX_set_cipher_list() failed. Cause: %s",
                     ERR_error_string(ERR_get_error(), nullptr)));
  }

#if OPENSSL_VERSION_NUMBER < 0x30000000L &&                                    \
    OPENSSL_VERSION_NUMBER >= 0x0090800fL
#  ifndef OPENSSL_NO_ECDH
  auto ecdh = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
  if (ecdh == nullptr) {
    A2_LOG_WARN(fmt("Failed to enable ECDHE cipher suites. Cause: %s",
                    ERR_error_string(ERR_get_error(), nullptr)));
  }
  else {
    SSL_CTX_set_tmp_ecdh(sslCtx_, ecdh);
    EC_KEY_free(ecdh);
  }
#  endif // OPENSSL_NO_ECDH
#endif   // OPENSSL_VERSION_NUMBER < 0x30000000L && OPENSSL_VERSION_NUMBER >=
         // 0x0090800fL
}

OpenSSLTLSContext::~OpenSSLTLSContext() { SSL_CTX_free(sslCtx_); }

bool OpenSSLTLSContext::good() const { return good_; }

bool OpenSSLTLSContext::addCredentialFile(const std::string& certfile,
                                          const std::string& keyfile)
{
  if (keyfile.empty()) {
    return addP12CredentialFile(certfile);
  }
  if (SSL_CTX_use_PrivateKey_file(sslCtx_, keyfile.c_str(), SSL_FILETYPE_PEM) !=
      1) {
    A2_LOG_ERROR(fmt("Failed to load private key from %s. Cause: %s",
                     keyfile.c_str(),
                     ERR_error_string(ERR_get_error(), nullptr)));
    return false;
  }
  if (SSL_CTX_use_certificate_chain_file(sslCtx_, certfile.c_str()) != 1) {
    A2_LOG_ERROR(fmt("Failed to load certificate from %s. Cause: %s",
                     certfile.c_str(),
                     ERR_error_string(ERR_get_error(), nullptr)));
    return false;
  }
  A2_LOG_INFO(fmt("Credential files(cert=%s, key=%s) were successfully added.",
                  certfile.c_str(), keyfile.c_str()));
  return true;
}
bool OpenSSLTLSContext::addP12CredentialFile(const std::string& p12file)
{
  std::stringstream ss;
  BufferedFile(p12file.c_str(), BufferedFile::READ).transfer(ss);

  auto data = ss.str();
  void* ptr = const_cast<char*>(data.c_str());
  size_t len = data.length();
  bio_t bio(BIO_new_mem_buf(ptr, len));

  if (!bio) {
    A2_LOG_ERROR("Failed to open PKCS12 file: no memory.");
    return false;
  }
  p12_t p12(d2i_PKCS12_bio(bio.get(), nullptr));
  if (!p12) {
    if (side_ == TLS_SERVER) {
      A2_LOG_ERROR(fmt("Failed to open PKCS12 file: %s. "
                       "If you meant to use PEM, you'll also have to specify "
                       "--rpc-private-key. See the manual.",
                       ERR_error_string(ERR_get_error(), nullptr)));
    }
    else {
      A2_LOG_ERROR(fmt("Failed to open PKCS12 file: %s. "
                       "If you meant to use PEM, you'll also have to specify "
                       "--private-key. See the manual.",
                       ERR_error_string(ERR_get_error(), nullptr)));
    }
    return false;
  }
  EVP_PKEY* pkey;
  X509* cert;
  STACK_OF(X509)* ca = nullptr;
  if (!PKCS12_parse(p12.get(), "", &pkey, &cert, &ca)) {
    if (side_ == TLS_SERVER) {
      A2_LOG_ERROR(fmt("Failed to parse PKCS12 file: %s. "
                       "If you meant to use PEM, you'll also have to specify "
                       "--rpc-private-key. See the manual.",
                       ERR_error_string(ERR_get_error(), nullptr)));
    }
    else {
      A2_LOG_ERROR(fmt("Failed to parse PKCS12 file: %s. "
                       "If you meant to use PEM, you'll also have to specify "
                       "--private-key. See the manual.",
                       ERR_error_string(ERR_get_error(), nullptr)));
    }
    return false;
  }

  pkey_t pkey_holder(pkey);
  x509_t cert_holder(cert);
  x509_sk_t ca_holder(ca);

  if (!pkey || !cert) {
    A2_LOG_ERROR(fmt("Failed to use PKCS12 file: no pkey or cert %s",
                     ERR_error_string(ERR_get_error(), nullptr)));
    return false;
  }
  if (!SSL_CTX_use_PrivateKey(sslCtx_, pkey)) {
    A2_LOG_ERROR(fmt("Failed to use PKCS12 file pkey: %s",
                     ERR_error_string(ERR_get_error(), nullptr)));
    return false;
  }
  if (!SSL_CTX_use_certificate(sslCtx_, cert)) {
    A2_LOG_ERROR(fmt("Failed to use PKCS12 file cert: %s",
                     ERR_error_string(ERR_get_error(), nullptr)));
    return false;
  }
  if (ca && sk_X509_num(ca) && !SSL_CTX_add_extra_chain_cert(sslCtx_, ca)) {
    A2_LOG_ERROR(fmt("Failed to use PKCS12 file chain: %s",
                     ERR_error_string(ERR_get_error(), nullptr)));
    return false;
  }

  A2_LOG_INFO("Using certificate and key from PKCS12 file");
  return true;
}

bool OpenSSLTLSContext::addSystemTrustedCACerts()
{
  if (SSL_CTX_set_default_verify_paths(sslCtx_) == 1) {
    A2_LOG_INFO("System trusted CA certificates were successfully added.");
    return true;
  }
#ifdef _WIN32
  if (addWindowsSystemCACerts(sslCtx_)) {
    A2_LOG_INFO("System trusted CA certificates were successfully added.");
    return true;
  }
#endif
  A2_LOG_INFO(fmt(MSG_LOADING_SYSTEM_TRUSTED_CA_CERTS_FAILED,
                  ERR_error_string(ERR_get_error(), nullptr)));
  return false;
}

bool OpenSSLTLSContext::addTrustedCACertFile(const std::string& certfile)
{
  if (SSL_CTX_load_verify_locations(sslCtx_, certfile.c_str(), nullptr) != 1) {
    A2_LOG_ERROR(fmt(MSG_LOADING_TRUSTED_CA_CERT_FAILED, certfile.c_str(),
                     ERR_error_string(ERR_get_error(), nullptr)));
    return false;
  }
  else {
    A2_LOG_INFO("Trusted CA certificates were successfully added.");
    return true;
  }
}

} // namespace aria2
