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
#include "Ed2kDownloadCommand.h"

#include <cstring>
#include <vector>

#include "Request.h"
#include "SocketCore.h"
#include "DownloadEngine.h"
#include "RequestGroup.h"
#include "SegmentMan.h"
#include "Segment.h"
#include "PieceStorage.h"
#include "DiskAdaptor.h"
#include "DownloadContext.h"
#include "FileEntry.h"
#include "Option.h"
#include "prefs.h"
#include "DlAbortEx.h"
#include "DlRetryEx.h"
#include "message.h"
#include "fmt.h"
#include "Logger.h"
#include "LogFactory.h"
#include "util.h"
#include "wallclock.h"
#include "A2STR.h"
#include "Ed2kHelper.h"
#include "error_code.h"

namespace aria2 {

// ED2K protocol constants
// ED2K_PART_SIZE: size of a "part" (chunk) for MD4 verification = 9.5MB
// ED2K_BLOCK_SIZE: standard block size for data requests = 180KB
static const int64_t ED2K_PART_SIZE = 9500000;
static const int64_t ED2K_BLOCK_SIZE = 184320;
static const size_t ED2K_HEADER_LEN = 4;
static const size_t ED2K_MAX_MSG_SIZE = 1024 * 1024 * 10; // 10MB max

// ED2K protocol message types
// Server protocol
namespace ed2kmsg {
  constexpr unsigned char LOGIN_REQUEST    = 0x01; // OP_LOGINREQUEST
  constexpr unsigned char ID_CHANGE        = 0x02; // OP_IDCHANGE (server login response)
  constexpr unsigned char SERVER_MESSAGE   = 0x04; // OP_SERVERMESSAGE
  constexpr unsigned char GET_FILE_SOURCES = 0x4A; // OP_GETFILESOURCES
  constexpr unsigned char FOUND_SOURCES    = 0x42; // OP_FOUNDSOURCES

  // Peer-to-peer protocol (same opcodes, different meaning in peer context)
  constexpr unsigned char HELLO            = 0x01; // OP_HELLO
  constexpr unsigned char HELLO_ANSWER     = 0x32; // OP_HELLOANSWER
  constexpr unsigned char START_UPLOAD_REQ = 0x40; // OP_STARTUPLOADREQ
  constexpr unsigned char ACCEPT_UPLOAD_REQ= 0x41; // OP_ACCEPTUPLOADREQ
  constexpr unsigned char END_UPLOAD_REQ   = 0x42; // OP_ENDUPLOADREQ (peer context)
  constexpr unsigned char SENDING_PART     = 0x46; // OP_SENDINGPART
  constexpr unsigned char REQUEST_PARTS    = 0x47; // OP_REQUESTPARTS
  constexpr unsigned char QUEUE_POSITION   = 0x36; // OP_QUEUERANKING
}

Ed2kDownloadCommand::Ed2kDownloadCommand(
    cuid_t cuid, const std::shared_ptr<Request>& req,
    const std::shared_ptr<FileEntry>& fileEntry, RequestGroup* requestGroup,
    DownloadEngine* e, const std::shared_ptr<SocketCore>& s)
    : AbstractCommand(cuid, req, fileEntry, requestGroup, e, s),
      fileHash_(),
      fileSize_(0),
      downloadedLength_(0),
      state_(Ed2kState::SERVER_LOGIN),
      downloadSubState_(DownloadSubState::REQUEST_PARTS),
      serverPort_(0),
      currentSourceIndex_(0),
      downloadOffset_(0),
      loginSent_(false),
      sourcesRequested_(false),
      helloSent_(false),
      uploadReqSent_(false),
      partsRequested_(false),
      requestStart_(0),
      requestEnd_(0)
{
  setTimeout(std::chrono::seconds(120));
  setReadCheckSocket(getSocket());
}

Ed2kDownloadCommand::~Ed2kDownloadCommand() = default;

bool Ed2kDownloadCommand::executeInternal()
{
  // Not used — execute() is overridden and handles the full state machine.
  return true;
}

void Ed2kDownloadCommand::setFileHash(const std::string& hash)
{
  fileHash_ = hash;
}

void Ed2kDownloadCommand::setFileSize(uint64_t size)
{
  fileSize_ = size;
}

void Ed2kDownloadCommand::setServerAddr(const std::string& addr,
                                         uint16_t port)
{
  serverAddr_ = addr;
  serverPort_ = port;
}

// ============================================================================
// Main execute() — state machine driver
// ============================================================================
bool Ed2kDownloadCommand::execute()
{
  A2_LOG_DEBUG(fmt("CUID#%" PRId64 " - Ed2kDownloadCommand::execute()"
                   " state=%d offset=%" PRId64 "/%" PRId64,
                   getCuid(), static_cast<int>(state_),
                   downloadOffset_, static_cast<int64_t>(fileSize_)));

  if (getRequestGroup()->downloadFinished() ||
      getRequestGroup()->isHaltRequested()) {
    return true;
  }

  // Check for inactivity timeout. The checkpoint is reset whenever data
  // is received (tryReceiveMessage) or sent (flushSendBuffer), so this
  // detects stalls where neither side makes progress.
  if (getCheckPoint().difference() > getTimeout()) {
    throw DL_RETRY_EX2(
        fmt("CUID#%" PRId64 " - ED2K timeout (state=%d, no data for %llds)",
            getCuid(), static_cast<int>(state_),
            static_cast<long long>(
                std::chrono::duration_cast<std::chrono::seconds>(
                    getCheckPoint().difference()).count())),
        error_code::TIME_OUT);
  }

  try {
    // Flush any pending outgoing data first.
    if (!flushSendBuffer()) {
      setWriteCheckSocket(getSocket());
      addCommandSelf();
      return false;
    }
    disableWriteCheckSocket();

    // State machine: each method returns true when its phase is complete
    // (and has updated state_ to the next phase), or false when it needs
    // to wait for I/O. We use a loop with continue for fall-through so
    // completed phases transition immediately without waiting for the
    // next execute() call.
    while (true) {
      switch (state_) {
      case Ed2kState::SERVER_LOGIN:
        if (!serverLogin()) {
          setReadCheckSocket(getSocket());
          addCommandSelf();
          return false;
        }
        state_ = Ed2kState::SERVER_GET_SOURCES;
        continue;

      case Ed2kState::SERVER_GET_SOURCES:
        if (!serverGetSources()) {
          setReadCheckSocket(getSocket());
          addCommandSelf();
          return false;
        }
        state_ = Ed2kState::PEER_CONNECT;
        continue;

      case Ed2kState::PEER_CONNECT:
        // peerConnect() always returns false — it either initiates a
        // non-blocking connection (setting state_ = PEER_HANDSHAKE) or
        // calls tryNextPeer() (setting state_ = PEER_CONNECT).
        peerConnect();
        addCommandSelf();
        return false;

      case Ed2kState::PEER_HANDSHAKE:
        if (!peerHandshake()) {
          // Only set read check if still in handshake state.
          // tryNextPeer() may have changed state_ to PEER_CONNECT,
          // in which case we must not set read check on the dead socket.
          if (state_ == Ed2kState::PEER_HANDSHAKE) {
            setReadCheckSocket(getSocket());
          }
          addCommandSelf();
          return false;
        }
        state_ = Ed2kState::PEER_START_UPLOAD;
        continue;

      case Ed2kState::PEER_START_UPLOAD:
        if (!peerStartUpload()) {
          if (state_ == Ed2kState::PEER_START_UPLOAD) {
            setReadCheckSocket(getSocket());
          }
          addCommandSelf();
          return false;
        }
        state_ = Ed2kState::PEER_DOWNLOAD;
        downloadSubState_ = DownloadSubState::REQUEST_PARTS;
        continue;

      case Ed2kState::PEER_DOWNLOAD:
        if (!peerDownload()) {
          if (state_ == Ed2kState::PEER_DOWNLOAD) {
            setReadCheckSocket(getSocket());
          }
          addCommandSelf();
          return false;
        }
        state_ = Ed2kState::FINISHED;
        continue;

      case Ed2kState::FINISHED:
        A2_LOG_INFO(fmt("CUID#%" PRId64 " - ED2K download completed"
                         " (%" PRId64 " bytes)",
                         getCuid(), downloadedLength_));
        return true;

      case Ed2kState::FAILURE:
      default:
        throw DL_ABORT_EX2("ED2K download failed",
                           error_code::UNKNOWN_ERROR);
      }
    }
  }
  catch (DlAbortEx& err) {
    getRequestGroup()->setLastErrorCode(err.getErrorCode(), err.what());
    A2_LOG_ERROR_EX(fmt("CUID#%" PRId64 " - ED2K download aborted: %s",
                        getCuid(), getRequest()->getUri().c_str()),
                    err);
    return true;
  }
  catch (DlRetryEx& err) {
    A2_LOG_INFO_EX(fmt("CUID#%" PRId64 " - ED2K download retry: %s",
                       getCuid(), getRequest()->getUri().c_str()),
                   err);
    return prepareForRetry(0);
  }
  catch (RecoverableException& err) {
    getRequestGroup()->setLastErrorCode(err.getErrorCode(), err.what());
    A2_LOG_ERROR_EX(fmt("CUID#%" PRId64 " - ED2K download error: %s",
                        getCuid(), getRequest()->getUri().c_str()),
                    err);
    return true;
  }
  catch (std::exception& err) {
    A2_LOG_ERROR(fmt("CUID#%" PRId64 " - ED2K unexpected error: %s",
                     getCuid(), err.what()));
    getRequestGroup()->setLastErrorCode(error_code::UNKNOWN_ERROR,
                                        err.what());
    return true;
  }
}

// ============================================================================
// Low-level protocol helpers
// ============================================================================

void Ed2kDownloadCommand::queueMessage(unsigned char msgType,
                                       const unsigned char* payload,
                                       size_t payloadLen)
{
  // ED2K message format:
  // [4 bytes: message length (LE, includes protocol byte + type byte + payload)]
  // [1 byte: protocol marker (0xE3 = eDonkey)]
  // [1 byte: message type]
  // [N bytes: payload]
  uint32_t msgLen = static_cast<uint32_t>(payloadLen + 2);
  unsigned char header[6];
  header[0] = static_cast<unsigned char>(msgLen);
  header[1] = static_cast<unsigned char>(msgLen >> 8);
  header[2] = static_cast<unsigned char>(msgLen >> 16);
  header[3] = static_cast<unsigned char>(msgLen >> 24);
  header[4] = 0xE3;  // eDonkey protocol marker
  header[5] = msgType;

  sendBuffer_.insert(sendBuffer_.end(), header, header + 6);
  if (payloadLen > 0 && payload) {
    sendBuffer_.insert(sendBuffer_.end(), payload, payload + payloadLen);
  }
}

bool Ed2kDownloadCommand::flushSendBuffer()
{
  if (sendBuffer_.empty()) {
    return true;
  }

  size_t totalWritten = 0;
  while (totalWritten < sendBuffer_.size()) {
    size_t toWrite = sendBuffer_.size() - totalWritten;
    ssize_t written = 0;
    try {
      written = getSocket()->writeData(sendBuffer_.data() + totalWritten,
                                        toWrite);
    }
    catch (RecoverableException&) {
      if (totalWritten > 0) {
        sendBuffer_.erase(sendBuffer_.begin(),
                          sendBuffer_.begin() + totalWritten);
      }
      return false;
    }
    if (written == 0) {
      // EAGAIN — socket buffer full, wait for writability.
      if (totalWritten > 0) {
        sendBuffer_.erase(sendBuffer_.begin(),
                          sendBuffer_.begin() + totalWritten);
      }
      return false;
    }
    totalWritten += static_cast<size_t>(written);
    // Reset inactivity timer on successful write
    getCheckPoint().reset();
  }

  sendBuffer_.clear();
  return true;
}

bool Ed2kDownloadCommand::tryReceiveMessage(
    unsigned char& msgType, std::vector<unsigned char>& payload)
{
  // Read whatever is available into recvBuffer_.
  unsigned char tmp[8192];
  size_t readLen = sizeof(tmp);
  getSocket()->readData(tmp, readLen);

  if (readLen > 0) {
    recvBuffer_.insert(recvBuffer_.end(), tmp, tmp + readLen);
    // Reset inactivity timer on received data
    getCheckPoint().reset();
  }
  else if (readLen == 0 && !getSocket()->wantRead()) {
    // readData returned 0 and wantRead is false → connection closed (EOF)
    throw DL_RETRY_EX("ED2K connection closed by remote peer");
  }

  // Need at least 4 bytes for the length prefix.
  if (recvBuffer_.size() < ED2K_HEADER_LEN) {
    return false;
  }

  uint32_t msgLen = static_cast<uint32_t>(recvBuffer_[0]) |
                    static_cast<uint32_t>(recvBuffer_[1]) << 8 |
                    static_cast<uint32_t>(recvBuffer_[2]) << 16 |
                    static_cast<uint32_t>(recvBuffer_[3]) << 24;

  if (msgLen > ED2K_MAX_MSG_SIZE) {
    throw DL_ABORT_EX2(fmt("ED2K message too large: %u bytes", msgLen),
                       error_code::UNKNOWN_ERROR);
  }
  // msgLen includes protocol byte + opcode byte, so minimum is 2
  if (msgLen < 2) {
    throw DL_ABORT_EX2("ED2K message too short",
                       error_code::UNKNOWN_ERROR);
  }

  size_t totalNeeded = ED2K_HEADER_LEN + msgLen;
  if (recvBuffer_.size() < totalNeeded) {
    return false;
  }

  // Skip protocol byte at recvBuffer_[ED2K_HEADER_LEN] (0xE3 or 0xC5)
  // unsigned char protocol = recvBuffer_[ED2K_HEADER_LEN];
  msgType = recvBuffer_[ED2K_HEADER_LEN + 1];
  size_t payloadLen = msgLen - 2;  // subtract protocol byte + opcode byte
  if (payloadLen > 0) {
    payload.assign(recvBuffer_.data() + ED2K_HEADER_LEN + 2,
                   recvBuffer_.data() + ED2K_HEADER_LEN + 2 + payloadLen);
  }
  else {
    payload.clear();
  }

  recvBuffer_.erase(recvBuffer_.begin(),
                    recvBuffer_.begin() + totalNeeded);
  return true;
}

// ============================================================================
// Server phase
// ============================================================================

bool Ed2kDownloadCommand::serverLogin()
{
  // Send OP_LOGINREQUEST (once)
  if (!loginSent_) {
    // Build login payload:
    //   [16 bytes] user_hash (random)
    //   [4 bytes]  user_id (0 = new connection)
    //   [2 bytes]  tcp_port (4662)
    //   [4 bytes]  client_version (0x3C = 60)
    //   [N+1]      username (null-terminated)
    //   [N+1]      password (null-terminated, empty for free servers)
    std::vector<unsigned char> payload;
    // User hash: fixed random-looking bytes (servers don't validate this)
    const unsigned char userHash[16] = {
      0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
      0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10
    };
    payload.insert(payload.end(), userHash, userHash + 16);
    // User ID = 0
    payload.push_back(0); payload.push_back(0);
    payload.push_back(0); payload.push_back(0);
    // TCP port = 4662 (LE)
    payload.push_back(0x36); payload.push_back(0x12);
    // Client version = 0x3C (60)
    payload.push_back(0x3C); payload.push_back(0);
    payload.push_back(0); payload.push_back(0);
    // Username = "XferCore\0"
    const char* username = "XferCore";
    payload.insert(payload.end(), username, username + 8);
    payload.push_back(0);
    // Password = "\0" (empty)
    payload.push_back(0);

    queueMessage(ed2kmsg::LOGIN_REQUEST, payload.data(), payload.size());
    loginSent_ = true;

    A2_LOG_INFO(fmt("CUID#%" PRId64 " - ED2K sending login request",
                    getCuid()));

    if (!flushSendBuffer()) {
      setWriteCheckSocket(getSocket());
      return false;
    }
  }

  // Receive OP_IDCHANGE (server's login response)
  unsigned char msgType;
  std::vector<unsigned char> payload;
  if (!tryReceiveMessage(msgType, payload)) {
    return false;
  }

  // Skip server messages (banner, MOTD, etc.)
  while (msgType == ed2kmsg::SERVER_MESSAGE) {
    A2_LOG_INFO(fmt("CUID#%" PRId64 " - ED2K server message: %s",
                    getCuid(),
                    payload.size() > 0 ?
                      std::string(payload.begin(), payload.end()).c_str() :
                      "(empty)"));
    if (!tryReceiveMessage(msgType, payload)) {
      return false;
    }
  }

  if (msgType != ed2kmsg::ID_CHANGE) {
    throw DL_ABORT_EX2(
        fmt("ED2K login failed: unexpected message type 0x%02x"
            " (expected 0x02 ID_CHANGE)", msgType),
        error_code::UNKNOWN_ERROR);
  }

  // Parse ID_CHANGE: [4 bytes user_id][optional 4 bytes tcp_flags]
  if (payload.size() >= 4) {
    uint32_t userId = static_cast<uint32_t>(payload[0]) |
                      (static_cast<uint32_t>(payload[1]) << 8) |
                      (static_cast<uint32_t>(payload[2]) << 16) |
                      (static_cast<uint32_t>(payload[3]) << 24);
    bool highId = userId >= 0x01000000;
    A2_LOG_INFO(fmt("CUID#%" PRId64 " - ED2K login accepted, user_id=%u (%s)",
                    getCuid(), userId, highId ? "HighID" : "LowID"));
  }

  return true;
}

bool Ed2kDownloadCommand::serverGetSources()
{
  // Send OP_GETFILESOURCES (once)
  if (!sourcesRequested_) {
    std::vector<unsigned char> rawHash =
        Ed2kHelper::hexToHash(fileHash_);
    if (rawHash.size() != 16) {
      throw DL_ABORT_EX2("Invalid ED2K file hash for source request",
                         error_code::UNKNOWN_ERROR);
    }

    queueMessage(ed2kmsg::GET_FILE_SOURCES, rawHash.data(), 16);
    sourcesRequested_ = true;

    A2_LOG_INFO(fmt("CUID#%" PRId64 " - ED2K requesting sources for hash=%s",
                    getCuid(), fileHash_.c_str()));

    if (!flushSendBuffer()) {
      setWriteCheckSocket(getSocket());
      return false;
    }
  }

  // Receive OP_FOUNDSOURCES
  unsigned char msgType;
  std::vector<unsigned char> payload;
  if (!tryReceiveMessage(msgType, payload)) {
    return false;
  }

  // Skip server messages
  while (msgType == ed2kmsg::SERVER_MESSAGE) {
    if (!tryReceiveMessage(msgType, payload)) {
      return false;
    }
  }

  if (msgType != ed2kmsg::FOUND_SOURCES) {
    throw DL_ABORT_EX2(
        fmt("ED2K source discovery failed: unexpected message type 0x%02x"
            " (expected 0x42 FOUND_SOURCES)", msgType),
        error_code::UNKNOWN_ERROR);
  }

  // Parse FOUND_SOURCES:
  //   [16 bytes] file_hash
  //   [1 byte]   source_count
  //   For each source: [4 bytes IP (LE)][2 bytes port (LE)]
  if (payload.size() < 17) {
    A2_LOG_WARN(fmt("CUID#%" PRId64 " - ED2K no sources found",
                    getCuid()));
    // No sources available — fail
    throw DL_ABORT_EX2("No ED2K sources found for this file",
                       error_code::UNKNOWN_ERROR);
  }

  uint8_t sourceCount = payload[16];
  A2_LOG_INFO(fmt("CUID#%" PRId64 " - ED2K found %u sources",
                  getCuid(), sourceCount));

  size_t expectedSize = 17 + static_cast<size_t>(sourceCount) * 6;
  if (payload.size() < expectedSize) {
    A2_LOG_WARN(fmt("CUID#%" PRId64 " - ED2K source list truncated"
                    " (expected %zu, got %zu)",
                    getCuid(), expectedSize, payload.size()));
    sourceCount = static_cast<uint8_t>(
        (payload.size() - 17) / 6);
  }

  for (size_t i = 0; i < sourceCount; ++i) {
    size_t off = 17 + i * 6;
    // IP is 4 bytes LE — first byte is first octet
    char ipStr[16];
    snprintf(ipStr, sizeof(ipStr), "%u.%u.%u.%u",
             payload[off], payload[off + 1],
             payload[off + 2], payload[off + 3]);
    // Port is 2 bytes LE
    uint16_t port = static_cast<uint16_t>(payload[off + 4]) |
                    (static_cast<uint16_t>(payload[off + 5]) << 8);

    // Skip LowID sources (can't connect directly)
    uint32_t ip = static_cast<uint32_t>(payload[off]) |
                  (static_cast<uint32_t>(payload[off + 1]) << 8) |
                  (static_cast<uint32_t>(payload[off + 2]) << 16) |
                  (static_cast<uint32_t>(payload[off + 3]) << 24);
    if (ip < 0x01000000) {
      A2_LOG_DEBUG(fmt("CUID#%" PRId64 " - Skipping LowID source %s:%u",
                       getCuid(), ipStr, port));
      continue;
    }

    PeerSource src;
    src.addr = ipStr;
    src.port = port;
    sources_.push_back(src);

    A2_LOG_INFO(fmt("CUID#%" PRId64 " - ED2K source %zu: %s:%u",
                    getCuid(), sources_.size(), ipStr, port));
  }

  if (sources_.empty()) {
    throw DL_ABORT_EX2("No connectable ED2K sources (all are LowID)",
                       error_code::UNKNOWN_ERROR);
  }

  // We're done with the server — close the server socket.
  // The peer phase will create its own socket.
  try {
    getSocket()->closeConnection();
  }
  catch (...) {}

  return true;
}

// ============================================================================
// Peer phase
// ============================================================================

void Ed2kDownloadCommand::tryNextPeer()
{
  currentSourceIndex_++;
  if (currentSourceIndex_ >= sources_.size()) {
    A2_LOG_ERROR(fmt("CUID#%" PRId64 " - ED2K exhausted all peer sources",
                     getCuid()));
    state_ = Ed2kState::FAILURE;
    return;
  }

  A2_LOG_INFO(fmt("CUID#%" PRId64 " - ED2K trying next peer source %zu/%zu",
                  getCuid(), currentSourceIndex_ + 1, sources_.size()));
  state_ = Ed2kState::PEER_CONNECT;
}

bool Ed2kDownloadCommand::peerConnect()
{
  if (currentSourceIndex_ >= sources_.size()) {
    state_ = Ed2kState::FAILURE;
    return false;
  }

  const PeerSource& src = sources_[currentSourceIndex_];

  A2_LOG_INFO(fmt("CUID#%" PRId64 " - ED2K connecting to peer %s:%u",
                  getCuid(), src.addr.c_str(), src.port));

  // Close old socket and clear all protocol state for the new peer.
  // This is critical: without clearing, stale data from the server phase
  // or a previous peer attempt would corrupt the new connection's protocol.
  disableReadCheckSocket();
  disableWriteCheckSocket();
  try {
    auto& oldSocket = getSocket();
    if (oldSocket && oldSocket->isOpen()) {
      oldSocket->closeConnection();
    }
  }
  catch (...) {}

  // Create a fresh socket for the peer connection
  createSocket();

  // Clear protocol buffers — new connection, new protocol context
  sendBuffer_.clear();
  recvBuffer_.clear();

  // Reset peer-phase flags so hello/upload/parts are re-sent
  helloSent_ = false;
  uploadReqSent_ = false;
  partsRequested_ = false;
  downloadSubState_ = DownloadSubState::REQUEST_PARTS;

  // Reset inactivity timer
  getCheckPoint().reset();

  try {
    getSocket()->establishConnection(src.addr, src.port);
  }
  catch (RecoverableException& e) {
    A2_LOG_WARN(fmt("CUID#%" PRId64 " - ED2K failed to connect to peer %s:%u: %s",
                    getCuid(), src.addr.c_str(), src.port, e.what()));
    tryNextPeer();
    return false;
  }

  // Connection initiated — transition to handshake state.
  // peerHandshake() will try to write (send OP_HELLO). If the connection
  // isn't established yet, writeData returns 0 (EAGAIN) and we wait
  // for writability. When connected, the socket becomes writable and
  // execute() is called again at PEER_HANDSHAKE state.
  state_ = Ed2kState::PEER_HANDSHAKE;
  setWriteCheckSocket(getSocket());
  return false;
}

bool Ed2kDownloadCommand::peerHandshake()
{
  try {
    // Send OP_HELLO (once)
    if (!helloSent_) {
      // Build OP_HELLO payload:
      //   [16 bytes] user_hash
      //   [4 bytes]  user_id (0)
      //   [2 bytes]  tcp_port (4662)
      //   [4 bytes]  server_ip (LE)
      //   [2 bytes]  server_port (LE)
      //   [N+1]      username (null-terminated)
      std::vector<unsigned char> payload;
      const unsigned char userHash[16] = {
        0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
        0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10
      };
      payload.insert(payload.end(), userHash, userHash + 16);
      // User ID = 0
      payload.push_back(0); payload.push_back(0);
      payload.push_back(0); payload.push_back(0);
      // TCP port = 4662
      payload.push_back(0x36); payload.push_back(0x12);
      // Server IP (convert string to LE uint32)
      uint32_t serverIp = 0;
      if (!serverAddr_.empty()) {
        serverIp = ntohl(inet_addr(serverAddr_.c_str()));
      }
      payload.push_back(static_cast<unsigned char>(serverIp));
      payload.push_back(static_cast<unsigned char>(serverIp >> 8));
      payload.push_back(static_cast<unsigned char>(serverIp >> 16));
      payload.push_back(static_cast<unsigned char>(serverIp >> 24));
      // Server port
      payload.push_back(static_cast<unsigned char>(serverPort_));
      payload.push_back(static_cast<unsigned char>(serverPort_ >> 8));
      // Username
      const char* username = "XferCore";
      payload.insert(payload.end(), username, username + 8);
      payload.push_back(0);

      queueMessage(ed2kmsg::HELLO, payload.data(), payload.size());
      helloSent_ = true;

      A2_LOG_DEBUG(fmt("CUID#%" PRId64 " - ED2K sending peer hello",
                       getCuid()));

      if (!flushSendBuffer()) {
        setWriteCheckSocket(getSocket());
        return false;
      }
    }

    // Receive OP_HELLOANSWER
    unsigned char msgType;
    std::vector<unsigned char> payload;
    if (!tryReceiveMessage(msgType, payload)) {
      return false;
    }

    // Skip queue ranking notifications (not relevant during handshake)
    while (msgType == ed2kmsg::QUEUE_POSITION) {
      if (!tryReceiveMessage(msgType, payload)) {
        return false;
      }
    }

    if (msgType != ed2kmsg::HELLO_ANSWER) {
      A2_LOG_WARN(fmt("CUID#%" PRId64 " - ED2K peer handshake: unexpected"
                      " message 0x%02x, trying next peer",
                      getCuid(), msgType));
      tryNextPeer();
      return false;
    }

    A2_LOG_INFO(fmt("CUID#%" PRId64 " - ED2K peer handshake completed",
                    getCuid()));
    return true;
  }
  catch (RecoverableException& e) {
    A2_LOG_WARN(fmt("CUID#%" PRId64 " - ED2K peer handshake error: %s,"
                    " trying next peer", getCuid(), e.what()));
    tryNextPeer();
    return false;
  }
}

bool Ed2kDownloadCommand::peerStartUpload()
{
  try {
    // Send OP_START_UPLOAD_REQ (once)
    // Payload: [16 bytes file_hash]
    if (!uploadReqSent_) {
      std::vector<unsigned char> rawHash =
          Ed2kHelper::hexToHash(fileHash_);
      if (rawHash.size() != 16) {
        throw DL_ABORT_EX2("Invalid ED2K file hash for upload request",
                           error_code::UNKNOWN_ERROR);
      }

      queueMessage(ed2kmsg::START_UPLOAD_REQ, rawHash.data(), 16);
      uploadReqSent_ = true;

      A2_LOG_INFO(fmt("CUID#%" PRId64 " - ED2K requesting upload slot",
                      getCuid()));

      if (!flushSendBuffer()) {
        setWriteCheckSocket(getSocket());
        return false;
      }
    }

    // Receive OP_ACCEPT_UPLOAD_REQ
    // The peer may send OP_QUEUE_POSITION (we're queued) before accepting.
    unsigned char msgType;
    std::vector<unsigned char> payload;
    while (true) {
      if (!tryReceiveMessage(msgType, payload)) {
        return false;
      }

      if (msgType == ed2kmsg::ACCEPT_UPLOAD_REQ) {
        A2_LOG_INFO(fmt("CUID#%" PRId64 " - ED2K upload slot accepted",
                        getCuid()));
        return true;
      }

      if (msgType == ed2kmsg::QUEUE_POSITION) {
        A2_LOG_DEBUG(fmt("CUID#%" PRId64 " - ED2K queued for upload slot",
                         getCuid()));
        continue;
      }

      if (msgType == ed2kmsg::END_UPLOAD_REQ) {
        A2_LOG_WARN(fmt("CUID#%" PRId64 " - ED2K peer refused upload,"
                        " trying next peer", getCuid()));
        tryNextPeer();
        return false;
      }

      A2_LOG_DEBUG(fmt("CUID#%" PRId64 " - ED2K skipping message 0x%02x"
                       " during upload request",
                       getCuid(), msgType));
    }
  }
  catch (RecoverableException& e) {
    A2_LOG_WARN(fmt("CUID#%" PRId64 " - ED2K upload request error: %s,"
                    " trying next peer", getCuid(), e.what()));
    tryNextPeer();
    return false;
  }
}

bool Ed2kDownloadCommand::peerDownload()
{
  try {
    while (downloadOffset_ < static_cast<int64_t>(fileSize_)) {
      switch (downloadSubState_) {
      case DownloadSubState::REQUEST_PARTS: {
        // Calculate block range: [downloadOffset_, end]
        requestStart_ = downloadOffset_;
        requestEnd_ = downloadOffset_ + ED2K_BLOCK_SIZE;
        if (requestEnd_ > static_cast<int64_t>(fileSize_)) {
          requestEnd_ = static_cast<int64_t>(fileSize_);
        }
        // Don't cross part boundary (ED2K_PART_SIZE)
        int64_t partBoundary =
            (downloadOffset_ / ED2K_PART_SIZE + 1) * ED2K_PART_SIZE;
        if (requestEnd_ > partBoundary) {
          requestEnd_ = partBoundary;
        }

        // Build OP_REQUEST_PARTS payload:
        //   [16 bytes] file_hash
        //   [3 x 4 bytes] start offsets (we request 1 block, others = 0)
        //   [3 x 4 bytes] end offsets (we request 1 block, others = 0)
        std::vector<unsigned char> rawHash =
            Ed2kHelper::hexToHash(fileHash_);
        if (rawHash.size() != 16) {
          throw DL_ABORT_EX2("Invalid ED2K file hash for parts request",
                             error_code::UNKNOWN_ERROR);
        }

        std::vector<unsigned char> payload;
        payload.insert(payload.end(), rawHash.begin(), rawHash.end());

        auto appendLe32 = [&payload](uint32_t v) {
          payload.push_back(static_cast<unsigned char>(v));
          payload.push_back(static_cast<unsigned char>(v >> 8));
          payload.push_back(static_cast<unsigned char>(v >> 16));
          payload.push_back(static_cast<unsigned char>(v >> 24));
        };
        appendLe32(static_cast<uint32_t>(requestStart_));
        appendLe32(0);
        appendLe32(0);
        appendLe32(static_cast<uint32_t>(requestEnd_));
        appendLe32(0);
        appendLe32(0);

        queueMessage(ed2kmsg::REQUEST_PARTS, payload.data(), payload.size());
        partsRequested_ = true;

        A2_LOG_DEBUG(fmt("CUID#%" PRId64 " - ED2K requesting block [%lld, %lld)",
                         getCuid(),
                         static_cast<long long>(requestStart_),
                         static_cast<long long>(requestEnd_)));

        if (!flushSendBuffer()) {
          setWriteCheckSocket(getSocket());
          return false;
        }

        downloadSubState_ = DownloadSubState::RECEIVING_DATA;
        // Fall through to try receiving immediately.
      }

      case DownloadSubState::RECEIVING_DATA: {
        unsigned char msgType;
        std::vector<unsigned char> payload;

        if (!tryReceiveMessage(msgType, payload)) {
          return false;
        }

        if (msgType == ed2kmsg::SENDING_PART) {
          // Parse SENDING_PART:
          //   [16 bytes] file_hash
          //   [4 bytes]  start_offset (LE)
          //   [4 bytes]  end_offset (LE)
          //   [data...]  file data (end_offset - start_offset bytes)
          if (payload.size() < 24) {
            throw DL_ABORT_EX2(
                fmt("ED2K SENDING_PART too short: %zu bytes",
                    payload.size()),
                error_code::UNKNOWN_ERROR);
          }

          uint32_t dataStart = static_cast<uint32_t>(payload[16]) |
                               (static_cast<uint32_t>(payload[17]) << 8) |
                               (static_cast<uint32_t>(payload[18]) << 16) |
                               (static_cast<uint32_t>(payload[19]) << 24);
          uint32_t dataEnd = static_cast<uint32_t>(payload[20]) |
                             (static_cast<uint32_t>(payload[21]) << 8) |
                             (static_cast<uint32_t>(payload[22]) << 16) |
                             (static_cast<uint32_t>(payload[23]) << 24);

          size_t expectedDataLen = dataEnd - dataStart;
          if (payload.size() < 24 + expectedDataLen) {
            throw DL_ABORT_EX2(
                "ED2K SENDING_PART data length mismatch",
                error_code::UNKNOWN_ERROR);
          }

          const unsigned char* fileData = payload.data() + 24;

          A2_LOG_DEBUG(fmt("CUID#%" PRId64 " - ED2K received block [%u, %u)"
                           " %zu bytes",
                           getCuid(), dataStart, dataEnd, expectedDataLen));

          if (!writeBlockToDisk(static_cast<int64_t>(dataStart),
                                fileData, expectedDataLen)) {
            throw DL_ABORT_EX2("ED2K failed to write block to disk",
                               error_code::FILE_IO_ERROR);
          }

          downloadedLength_ += static_cast<int64_t>(expectedDataLen);
          downloadOffset_ = static_cast<int64_t>(dataEnd);

          updateProgress();

          downloadSubState_ = DownloadSubState::REQUEST_PARTS;
          break;
        }

        if (msgType == ed2kmsg::END_UPLOAD_REQ) {
          A2_LOG_INFO(fmt("CUID#%" PRId64 " - ED2K peer ended upload,"
                          " trying next peer", getCuid()));
          tryNextPeer();
          return false;
        }

        A2_LOG_DEBUG(fmt("CUID#%" PRId64 " - ED2K skipping message 0x%02x"
                         " during download",
                         getCuid(), msgType));
        break;
      }
      } // switch (downloadSubState_)
    } // while (downloadOffset_ < fileSize_)

    // All data downloaded — mark as complete
    try {
      auto ps = getRequestGroup()->getPieceStorage();
      if (ps) {
        ps->markAllPiecesDone();
      }
    }
    catch (RecoverableException& e) {
      A2_LOG_DEBUG(fmt("CUID#%" PRId64 " - ED2K: markAllPiecesDone failed: %s",
                       getCuid(), e.what()));
    }

    return true;
  }
  catch (RecoverableException& e) {
    A2_LOG_WARN(fmt("CUID#%" PRId64 " - ED2K download error: %s,"
                    " trying next peer", getCuid(), e.what()));
    tryNextPeer();
    return false;
  }
}

// ============================================================================
// Disk I/O and progress
// ============================================================================

bool Ed2kDownloadCommand::writeBlockToDisk(int64_t offset,
                                           const unsigned char* data,
                                           size_t len)
{
  if (len == 0) {
    return true;
  }

  try {
    auto ps = getRequestGroup()->getPieceStorage();
    if (!ps || !ps->getDiskAdaptor()) {
      A2_LOG_ERROR(fmt("CUID#%" PRId64 " - ED2K: no disk adaptor available",
                       getCuid()));
      return false;
    }
    ps->getDiskAdaptor()->writeData(data, len, offset);
    return true;
  }
  catch (RecoverableException& e) {
    A2_LOG_ERROR_EX(fmt("CUID#%" PRId64 " - ED2K disk write failed at"
                        " offset %" PRId64 ": %s",
                        getCuid(), offset, e.what()),
                    e);
    return false;
  }
}

void Ed2kDownloadCommand::updateProgress()
{
  try {
    auto ps = getRequestGroup()->getPieceStorage();
    if (!ps) {
      return;
    }
    auto dc = getDownloadContext();
    if (dc && dc->getPieceLength() > 0) {
      // markPiecesDone sets the bitfield for all pieces up to
      // downloadedLength_, which matches ED2K's sequential download order.
      ps->markPiecesDone(downloadedLength_);
    }
  }
  catch (RecoverableException& e) {
    A2_LOG_DEBUG(fmt("CUID#%" PRId64 " - ED2K: updateProgress failed: %s",
                     getCuid(), e.what()));
  }
}

} // namespace aria2
