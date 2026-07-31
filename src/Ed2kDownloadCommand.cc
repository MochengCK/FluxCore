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
 * version of the file(s), then also delete this exception statement
 * in each source file.  If you do not wish to do so, delete this
 * exception statement from all source files.
 */
/* copyright --> */
#include "Ed2kDownloadCommand.h"

#include <cstring>
#include <vector>
#include <algorithm>
#include <chrono>

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
#include "a2netcompat.h"

namespace aria2 {

// ED2K protocol constants
static const int64_t ED2K_PART_SIZE = 9500000;    // 9.5MB part size for MD4
static const int64_t ED2K_BLOCK_SIZE = 184320;     // 180KB standard block size
static const size_t ED2K_HEADER_LEN = 4;
static const size_t ED2K_MAX_MSG_SIZE = 1024 * 1024 * 10; // 10MB max

// ED2K tag types (eDonkey protocol tag encoding)
namespace ed2ktag {
  constexpr unsigned char TYPE_STRING = 0x01;
  constexpr unsigned char TYPE_INT32  = 0x02;

  // Tag IDs (1-byte numeric names, used with 0x80 flag)
  constexpr unsigned char CT_NAME         = 0x01; // Username
  constexpr unsigned char CT_VERSION      = 0x11; // Client version
  constexpr unsigned char CT_SERVER_FLAGS = 0x20; // Server capability flags
}

// Append a string tag with 1-byte numeric name to payload.
// Format: [0x80|TYPE_STRING][tag_id][2-byte length LE][string data]
static void append_string_tag(std::vector<unsigned char>& payload,
                              unsigned char tagId,
                              const std::string& value)
{
  payload.push_back(static_cast<unsigned char>(
      ed2ktag::TYPE_STRING | 0x80));
  payload.push_back(tagId);
  uint16_t len = static_cast<uint16_t>(value.size());
  payload.push_back(static_cast<unsigned char>(len));
  payload.push_back(static_cast<unsigned char>(len >> 8));
  payload.insert(payload.end(), value.begin(), value.end());
}

// Append an int32 tag with 1-byte numeric name to payload.
// Format: [0x80|TYPE_INT32][tag_id][4-byte int32 LE]
static void append_int32_tag(std::vector<unsigned char>& payload,
                             unsigned char tagId,
                             uint32_t value)
{
  payload.push_back(static_cast<unsigned char>(
      ed2ktag::TYPE_INT32 | 0x80));
  payload.push_back(tagId);
  payload.push_back(static_cast<unsigned char>(value));
  payload.push_back(static_cast<unsigned char>(value >> 8));
  payload.push_back(static_cast<unsigned char>(value >> 16));
  payload.push_back(static_cast<unsigned char>(value >> 24));
}

// ED2K protocol message types
namespace ed2kmsg {
  // Server protocol
  constexpr unsigned char LOGIN_REQUEST    = 0x01; // OP_LOGINREQUEST
  constexpr unsigned char ID_CHANGE        = 0x02; // OP_IDCHANGE
  constexpr unsigned char SERVER_MESSAGE   = 0x04; // OP_SERVERMESSAGE
  constexpr unsigned char GET_FILE_SOURCES = 0x4A; // OP_GETFILESOURCES
  constexpr unsigned char FOUND_SOURCES    = 0x42; // OP_FOUNDSOURCES

  // Peer-to-peer protocol
  constexpr unsigned char HELLO            = 0x01; // OP_HELLO
  constexpr unsigned char HELLO_ANSWER     = 0x32; // OP_HELLOANSWER
  constexpr unsigned char START_UPLOAD_REQ = 0x40; // OP_STARTUPLOADREQ
  constexpr unsigned char ACCEPT_UPLOAD_REQ= 0x41; // OP_ACCEPTUPLOADREQ
  constexpr unsigned char END_UPLOAD_REQ   = 0x42; // OP_ENDUPLOADREQ
  constexpr unsigned char SENDING_PART     = 0x46; // OP_SENDINGPART
  constexpr unsigned char REQUEST_PARTS    = 0x47; // OP_REQUESTPARTS
  constexpr unsigned char QUEUE_POSITION   = 0x36; // OP_QUEUERANKING
  // Source exchange (peer-to-peer)
  constexpr unsigned char SOURCES_REQUEST  = 0x16; // OP_SOURCESREQUEST
  constexpr unsigned char SOURCES_ANSWER   = 0x17; // OP_SOURCESANSWER
}

Ed2kDownloadCommand::Ed2kDownloadCommand(
    cuid_t cuid, const std::shared_ptr<Request>& req,
    const std::shared_ptr<FileEntry>& fileEntry, RequestGroup* requestGroup,
    DownloadEngine* e, const std::shared_ptr<SocketCore>& s)
    : AbstractCommand(cuid, req, fileEntry, requestGroup, e, s),
      fileHash_(),
      fileSize_(0),
      downloadedLength_(0),
      state_(Ed2kState::SERVER_CONNECT),
      downloadSubState_(DownloadSubState::REQUEST_PARTS),
      serverPort_(0),
      currentServerIndex_(0),
      serverRound_(0),
      currentSourceIndex_(0),
      serverSourceEnabled_(true),
      sourceExchangeEnabled_(true),
      kadEnabled_(false),
      sourceExchangeInterval_(300),
      sourceExchangeSent_(false),
      maxSources_(100),
      currentKadNodeIndex_(0),
      kadBootstrapSent_(false),
      kadState_(KadState::BOOTSTRAP),
      partSize_(ED2K_PART_SIZE),
      downloadOffset_(0),
      lastMarkedLength_(0),
      loginSent_(false),
      sourcesRequested_(false),
      helloSent_(false),
      uploadReqSent_(false),
      partsRequested_(false),
      connectionError_(false),
      requestStart_(0),
      requestEnd_(0)
{
  setTimeout(std::chrono::seconds(120));
  // Don't set readCheckSocket here — the socket from
  // Ed2kInitiateConnectionCommand is mid non-blocking connect.
  // serverConnect() will set the appropriate event check (writeCheck).
  disableReadCheckSocket();

  // Load source discovery configuration from options.
  auto opt = getOption();
  if (opt) {
    serverSourceEnabled_ = opt->getAsBool(PREF_ED2K_SERVER_SOURCE_ENABLED);
    sourceExchangeEnabled_ = opt->getAsBool(PREF_ED2K_SOURCE_EXCHANGE_ENABLED);
    kadEnabled_ = opt->getAsBool(PREF_ED2K_KAD_ENABLED);
    int interval = opt->getAsInt(PREF_ED2K_SOURCE_EXCHANGE_INTERVAL);
    if (interval > 0) {
      sourceExchangeInterval_ = interval;
    }
    int maxSrc = opt->getAsInt(PREF_ED2K_MAX_SOURCES_PER_FILE);
    if (maxSrc > 0) {
      maxSources_ = maxSrc;
    }
  }
  A2_LOG_INFO(fmt("CUID#%" PRId64 " - ED2K source discovery config:"
                  " server=%d sourceExchange=%d kad=%d interval=%ds maxSources=%d",
                  getCuid(), serverSourceEnabled_ ? 1 : 0,
                  sourceExchangeEnabled_ ? 1 : 0,
                  kadEnabled_ ? 1 : 0, sourceExchangeInterval_, maxSources_));

  // Initialize KAD if enabled.
  if (kadEnabled_) {
    initKad();
  }

  // Resume support: if PieceStorage already has progress (e.g. after a
  // timeout/retry), initialize downloadOffset_ and downloadedLength_ from
  // the completed length so we don't re-download from the beginning.
  auto ps = getRequestGroup()->getPieceStorage();
  if (ps) {
    int64_t completed = ps->getCompletedLength();
    if (completed > 0) {
      downloadedLength_ = completed;
      downloadOffset_ = completed;
      lastMarkedLength_ = completed;
      A2_LOG_INFO(fmt("CUID#%" PRId64 " - ED2K: resuming from offset %" PRId64,
                      getCuid(), completed));
    }
  }
}

Ed2kDownloadCommand::~Ed2kDownloadCommand() = default;

bool Ed2kDownloadCommand::executeInternal()
{
  // Not used — execute() is overridden.
  return true;
}

void Ed2kDownloadCommand::setFileHash(const std::string& hash)
{
  fileHash_ = hash;
}

void Ed2kDownloadCommand::setFileSize(uint64_t size)
{
  fileSize_ = size;
  // Build the Part Availability Manager table now that file size is known.
  // This drives rarest-first scheduling across peers' available parts.
  initParts();
}

void Ed2kDownloadCommand::setServerAddr(const std::string& addr,
                                         uint16_t port)
{
  serverAddr_ = addr;
  serverPort_ = port;
}

void Ed2kDownloadCommand::setServerList(
    const std::vector<std::pair<std::string, uint16_t>>& servers)
{
  serverList_ = servers;
}

// ============================================================================
// Main execute() — state machine driver
//
// Key design principles (learned from BT's PeerInteractionCommand):
// 1. Never block on I/O — always return false and re-queue (addCommandSelf)
//    when data isn't available, letting the EventPoll wake us up.
// 2. Set proper read/write check sockets before returning false, so the
//    EventPoll knows when to wake us.
// 3. Skip flushSendBuffer() in transition states (SERVER_CONNECT, PEER_CONNECT)
//    to avoid writing stale data to dead sockets.
// 4. Handle connection errors by trying the next peer/server, not by
//    restarting the entire download.
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

  // Check for inactivity timeout.
  if (getCheckPoint().difference() > getTimeout()) {
    throw DL_RETRY_EX2(
        fmt("CUID#%" PRId64 " - ED2K timeout (state=%d, no activity for %llds)",
            getCuid(), static_cast<int>(state_),
            static_cast<long long>(
                std::chrono::duration_cast<std::chrono::seconds>(
                    getCheckPoint().difference()).count())),
        error_code::TIME_OUT);
  }

  try {
    // Flush pending outgoing data — but ONLY in states that use the
    // current socket for active protocol exchange. In transition states
    // (SERVER_CONNECT, PEER_CONNECT, PEER_WAIT_CONNECT) we may be about
    // to switch sockets, so flushing stale data to the old socket would
    // cause errors or hang the state machine.
    if (state_ != Ed2kState::SERVER_CONNECT &&
        state_ != Ed2kState::PEER_CONNECT &&
        state_ != Ed2kState::PEER_WAIT_CONNECT) {
      if (!flushSendBuffer()) {
        if (connectionError_) {
          // Socket is dead — handle the error
          connectionError_ = false;
          sendBuffer_.clear();
          recvBuffer_.clear();
          if (state_ == Ed2kState::SERVER_LOGIN ||
              state_ == Ed2kState::SERVER_GET_SOURCES ||
              state_ == Ed2kState::SERVER_WAIT_SOURCES) {
            A2_LOG_WARN(fmt("CUID#%" PRId64 " - ED2K: server socket dead,"
                            " trying next server", getCuid()));
            currentServerIndex_++;
            state_ = Ed2kState::SERVER_CONNECT;
          }
          else {
            A2_LOG_WARN(fmt("CUID#%" PRId64 " - ED2K: peer socket dead,"
                            " trying next peer", getCuid()));
            tryNextPeer();
          }
          addCommandSelf();
          return false;
        }
        // EAGAIN — wait for socket to become writable
        setWriteCheckSocket(getSocket());
        addCommandSelf();
        return false;
      }
      disableWriteCheckSocket();
    }

    // State machine
    while (true) {
      switch (state_) {
      case Ed2kState::SERVER_CONNECT:
        // If server-based source discovery is disabled, skip directly
        // to peer connection (sources must come from elsewhere —
        // e.g. source exchange or KAD-provided sources).
        if (!serverSourceEnabled_ && sources_.empty()) {
          A2_LOG_INFO(fmt("CUID#%" PRId64
                          " - ED2K: server source disabled, no sources yet",
                          getCuid()));
          // No sources and no server — wait and retry periodically
          if (sourceWaitStart_.difference() > std::chrono::seconds(60)) {
            sourceWaitStart_.reset();
            A2_LOG_WARN(fmt("CUID#%" PRId64
                            " - ED2K: no sources available, retrying",
                            getCuid()));
          }
          addCommandSelf();
          return false;
        }
        if (!serverSourceEnabled_) {
          // Have sources from elsewhere — go straight to peer connection
          state_ = Ed2kState::PEER_CONNECT;
          continue;
        }
        if (!serverConnect()) {
          // serverConnect() handles its own event registration
          addCommandSelf();
          return false;
        }
        // Connection established
        state_ = Ed2kState::SERVER_LOGIN;
        continue;

      case Ed2kState::SERVER_LOGIN:
        if (!serverLogin()) {
          if (state_ == Ed2kState::SERVER_LOGIN) {
            setReadCheckSocket(getSocket());
          }
          addCommandSelf();
          return false;
        }
        state_ = Ed2kState::SERVER_GET_SOURCES;
        continue;

      case Ed2kState::SERVER_GET_SOURCES:
        if (!serverGetSources()) {
          if (state_ == Ed2kState::SERVER_GET_SOURCES) {
            setReadCheckSocket(getSocket());
          }
          addCommandSelf();
          return false;
        }
        // serverGetSources transitions state_ itself
        continue;

      case Ed2kState::SERVER_WAIT_SOURCES:
        if (!serverWaitSources()) {
          addCommandSelf();
          return false;
        }
        continue;

      case Ed2kState::PEER_CONNECT:
        peerConnect();
        // peerConnect sets state_ to PEER_WAIT_CONNECT (or handles error)
        if (state_ == Ed2kState::PEER_WAIT_CONNECT) {
          setWriteCheckSocket(getSocket());
        }
        addCommandSelf();
        return false;

      case Ed2kState::PEER_WAIT_CONNECT:
        if (!peerWaitConnect()) {
          setWriteCheckSocket(getSocket());
          addCommandSelf();
          return false;
        }
        // Connection established — transition to handshake
        state_ = Ed2kState::PEER_HANDSHAKE;
        continue;

      case Ed2kState::PEER_HANDSHAKE:
        if (!peerHandshake()) {
          if (state_ == Ed2kState::PEER_HANDSHAKE) {
            setReadCheckSocket(getSocket());
          }
          addCommandSelf();
          return false;
        }
        // After handshake, optionally ask peer for additional sources
        // before requesting upload.
        if (sourceExchangeEnabled_) {
          state_ = Ed2kState::PEER_SOURCE_EXCHANGE;
          sourceExchangeSent_ = false;
        }
        else {
          state_ = Ed2kState::PEER_START_UPLOAD;
        }
        continue;

      case Ed2kState::PEER_SOURCE_EXCHANGE:
        if (!peerSourceExchange()) {
          if (state_ == Ed2kState::PEER_SOURCE_EXCHANGE) {
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
  // eDonkey packet format: [4-byte length LE][0xE3 protocol][opcode][payload]
  // length field = bytes after the length field = 1(protocol) + 1(opcode) + payloadLen
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
    catch (RecoverableException& e) {
      // Real error (not EAGAIN) — connection is dead.
      // SocketCore::writeData returns 0 for EAGAIN, only throws for
      // real errors like ECONNRESET, EPIPE, etc.
      if (totalWritten > 0) {
        sendBuffer_.erase(sendBuffer_.begin(),
                          sendBuffer_.begin() + totalWritten);
      }
      connectionError_ = true;
      A2_LOG_WARN(fmt("CUID#%" PRId64 " - ED2K: socket write error: %s",
                      getCuid(), e.what()));
      return false;
    }
    if (written == 0) {
      // EAGAIN — socket buffer full or connection not ready
      if (totalWritten > 0) {
        sendBuffer_.erase(sendBuffer_.begin(),
                          sendBuffer_.begin() + totalWritten);
      }
      return false;
    }
    totalWritten += static_cast<size_t>(written);
    getCheckPoint().reset();
  }

  sendBuffer_.clear();
  return true;
}

bool Ed2kDownloadCommand::tryReceiveMessage(
    unsigned char& msgType, std::vector<unsigned char>& payload)
{
  unsigned char tmp[8192];
  size_t readLen = sizeof(tmp);
  getSocket()->readData(tmp, readLen);

  if (readLen > 0) {
    recvBuffer_.insert(recvBuffer_.end(), tmp, tmp + readLen);
    getCheckPoint().reset();
  }
  else if (readLen == 0 && !getSocket()->wantRead()) {
    // Connection closed (EOF)
    throw DL_RETRY_EX("ED2K connection closed by remote peer");
  }

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
  if (msgLen < 2) {
    throw DL_ABORT_EX2("ED2K message too short",
                       error_code::UNKNOWN_ERROR);
  }

  size_t totalNeeded = ED2K_HEADER_LEN + msgLen;
  if (recvBuffer_.size() < totalNeeded) {
    return false;
  }

  // Validate the eDonkey protocol byte (offset 4).
  // 0xE3 = standard eDonkey protocol (what we handle).
  // 0xE4 = eMule compressed packet — not supported here, skip.
  unsigned char protocolByte = recvBuffer_[ED2K_HEADER_LEN];
  if (protocolByte != 0xE3) {
    A2_LOG_WARN(fmt("CUID#%" PRId64 " - ED2K: unexpected protocol byte 0x%02x"
                    " (expected 0xE3), skipping %u-byte message",
                    getCuid(), protocolByte, msgLen));
    recvBuffer_.erase(recvBuffer_.begin(),
                      recvBuffer_.begin() + totalNeeded);
    // Return false so caller re-enters to try parsing the next message.
    return false;
  }

  msgType = recvBuffer_[ED2K_HEADER_LEN + 1];
  size_t payloadLen = msgLen - 2;
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

bool Ed2kDownloadCommand::serverConnect()
{
  // This method handles the full non-blocking connect lifecycle for
  // ED2K servers. It handles two cases:
  //
  // 1. Initial call: socket was passed from Ed2kInitiateConnectionCommand
  //    with a pending non-blocking connect. We check if it completed.
  //
  // 2. Reconnection: socket was closed (after exhausting peer sources or
  //    server wait timeout). We create a new socket and connect.

  // Check if we have an existing socket with a pending non-blocking connect.
  if (getSocket() && getSocket()->isOpen()) {
    // Check if the non-blocking connect has completed.
    // isWritable(0) uses poll() with 0 timeout — returns true immediately
    // if the socket is writable (connected or error).
    if (!getSocket()->isWritable(0)) {
      // Connection still in progress — wait for write event
      A2_LOG_DEBUG(fmt("CUID#%" PRId64 " - ED2K: waiting for server"
                       " connection to %s:%u",
                       getCuid(), serverAddr_.c_str(), serverPort_));
      setWriteCheckSocket(getSocket());
      return false;
    }

    // Socket is writable — check for connection errors via SO_ERROR.
    // This is the standard non-blocking connect completion check,
    // same pattern used by AbstractCommand::checkIfConnectionEstablished().
    std::string err = getSocket()->getSocketError();
    if (!err.empty()) {
      A2_LOG_WARN(fmt("CUID#%" PRId64 " - ED2K: server connection to"
                      " %s:%u failed: %s, trying next server",
                      getCuid(), serverAddr_.c_str(), serverPort_,
                      err.c_str()));
      // Close failed socket and try next server
      disableReadCheckSocket();
      disableWriteCheckSocket();
      try { getSocket()->closeConnection(); } catch (...) {}
      currentServerIndex_++;
      // Fall through to create new connection
    }
    else {
      // Connection established!
      A2_LOG_INFO(fmt("CUID#%" PRId64 " - ED2K: server connection"
                      " established to %s:%u",
                      getCuid(), serverAddr_.c_str(), serverPort_));
      getCheckPoint().reset();
      loginSent_ = false;
      sourcesRequested_ = false;
      return true;
    }
  }

  // Build server list if empty
  if (serverList_.empty()) {
    if (!serverAddr_.empty() && serverPort_ > 0) {
      serverList_.push_back({serverAddr_, serverPort_});
    }
    if (serverList_.empty()) {
      std::vector<Ed2kServerEntry> defaults;
      Ed2kHelper::getDefaultServers(defaults);
      for (const auto& s : defaults) {
        serverList_.push_back({s.addr, s.port});
      }
    }
  }

  // Pick next server (with round limiting)
  if (currentServerIndex_ >= serverList_.size()) {
    currentServerIndex_ = 0;
    serverRound_++;
    if (serverRound_ > MAX_SERVER_ROUNDS) {
      A2_LOG_ERROR(fmt("CUID#%" PRId64 " - ED2K: exhausted all server rounds",
                       getCuid()));
      state_ = Ed2kState::FAILURE;
      return false;
    }
    A2_LOG_INFO(fmt("CUID#%" PRId64 " - ED2K: starting server round %d",
                    getCuid(), serverRound_));
  }

  const auto& server = serverList_[currentServerIndex_];
  A2_LOG_INFO(fmt("CUID#%" PRId64 " - ED2K: connecting to server %s:%u"
                  " (round %d, server %zu/%zu)",
                  getCuid(), server.first.c_str(), server.second,
                  serverRound_, currentServerIndex_ + 1,
                  serverList_.size()));

  // Clean up any old socket state before creating a new one
  disableReadCheckSocket();
  disableWriteCheckSocket();
  sendBuffer_.clear();
  recvBuffer_.clear();
  loginSent_ = false;
  sourcesRequested_ = false;

  try {
    createSocket();
    getSocket()->establishConnection(server.first, server.second);
    serverAddr_ = server.first;
    serverPort_ = server.second;
  }
  catch (RecoverableException& e) {
    A2_LOG_WARN(fmt("CUID#%" PRId64 " - ED2K: failed to initiate connection"
                    " to server %s:%u: %s",
                    getCuid(), server.first.c_str(), server.second,
                    e.what()));
    currentServerIndex_++;
    // No event check set — will retry on next execute() call
    // (triggered by the 1s poll timeout)
    return false;
  }

  // Non-blocking connect initiated — wait for write event.
  // The write event will fire when the connection completes (success
  // or failure). On the next execute() call, we'll re-enter
  // serverConnect() and check isWritable(0) + SO_ERROR.
  setWriteCheckSocket(getSocket());
  return false;
}

bool Ed2kDownloadCommand::serverLogin()
{
  try {
    // Send OP_LOGINREQUEST (once)
    if (!loginSent_) {
      // OP_LOGINREQUEST payload (eDonkey tag-based format):
      //   [16 bytes] user_hash (MD4)
      //   [4 bytes]  client_id (0 for new login)
      //   [2 bytes]  TCP port (LE, 4662 = 0x36 0x12)
      //   [4 bytes]  tag_count (LE)
      //   [tags...]  tag list
      //
      // Tags:
      //   CT_NAME (0x01)     — username string
      //   CT_VERSION (0x11)  — client version int32 (0x3C = eMule 0.60)
      //   CT_SERVER_FLAGS (0x20) — capability flags int32
      std::vector<unsigned char> payload;
      const unsigned char userHash[16] = {
        0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
        0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10
      };
      payload.insert(payload.end(), userHash, userHash + 16);
      // Client ID = 0 (new connection)
      payload.push_back(0); payload.push_back(0);
      payload.push_back(0); payload.push_back(0);
      // TCP port = 4662 (LE)
      payload.push_back(0x36); payload.push_back(0x12);
      // Tag count = 3 (LE uint32)
      payload.push_back(3); payload.push_back(0);
      payload.push_back(0); payload.push_back(0);
      // Tag 1: CT_NAME = "eMule"
      append_string_tag(payload, ed2ktag::CT_NAME, "eMule");
      // Tag 2: CT_VERSION = 0x3C (eMule 0.60)
      append_int32_tag(payload, ed2ktag::CT_VERSION, 0x3C);
      // Tag 3: CT_SERVER_FLAGS = 0x21 (public server + new tags + unicode)
      append_int32_tag(payload, ed2ktag::CT_SERVER_FLAGS, 0x21);

      queueMessage(ed2kmsg::LOGIN_REQUEST, payload.data(), payload.size());
      loginSent_ = true;

      A2_LOG_INFO(fmt("CUID#%" PRId64 " - ED2K sending login request to %s:%u",
                      getCuid(), serverAddr_.c_str(), serverPort_));

      if (!flushSendBuffer()) {
        if (connectionError_) {
          // Socket is dead — let execute() handle it
          return false;
        }
        setWriteCheckSocket(getSocket());
        return false;
      }
    }

    // Receive OP_IDCHANGE
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
      A2_LOG_WARN(fmt("CUID#%" PRId64 " - ED2K login: unexpected msg 0x%02x,"
                      " trying next server", getCuid(), msgType));
      // Server didn't accept login — try next server
      disableReadCheckSocket();
      disableWriteCheckSocket();
      try { getSocket()->closeConnection(); } catch (...) {}
      currentServerIndex_++;
      state_ = Ed2kState::SERVER_CONNECT;
      return false;
    }

    // Parse ID_CHANGE: [4 bytes user_id][optional 4 bytes tcp_flags]
    if (payload.size() >= 4) {
      uint32_t userId = static_cast<uint32_t>(payload[0]) |
                        (static_cast<uint32_t>(payload[1]) << 8) |
                        (static_cast<uint32_t>(payload[2]) << 16) |
                        (static_cast<uint32_t>(payload[3]) << 24);
      bool highId = userId >= 0x01000000;
      A2_LOG_INFO(fmt("CUID#%" PRId64 " - ED2K login accepted, user_id=%u"
                      " (%s)", getCuid(), userId,
                      highId ? "HighID" : "LowID"));
    }

    return true;
  }
  catch (RecoverableException& e) {
    A2_LOG_WARN(fmt("CUID#%" PRId64 " - ED2K server login error: %s,"
                    " trying next server", getCuid(), e.what()));
    disableReadCheckSocket();
    disableWriteCheckSocket();
    try { if (getSocket()) getSocket()->closeConnection(); } catch (...) {}
    currentServerIndex_++;
    state_ = Ed2kState::SERVER_CONNECT;
    return false;
  }
}

bool Ed2kDownloadCommand::serverGetSources()
{
  try {
    // Send OP_GETFILESOURCES (once per server session)
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
        if (connectionError_) {
          return false;
        }
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
      A2_LOG_WARN(fmt("CUID#%" PRId64 " - ED2K: unexpected msg 0x%02x"
                      " (expected FOUND_SOURCES 0x42)",
                      getCuid(), msgType));
      // Treat as "no sources" — enter wait state
      state_ = Ed2kState::SERVER_WAIT_SOURCES;
      sourceWaitStart_.reset();
      return true;
    }

    // Parse FOUND_SOURCES:
    //   [16 bytes] file_hash
    //   [1 byte]   source_count
    //   For each source: [4 bytes IP (LE)][2 bytes port (LE)]
    if (payload.size() < 17) {
      A2_LOG_INFO(fmt("CUID#%" PRId64 " - ED2K: no sources in response",
                      getCuid()));
      state_ = Ed2kState::SERVER_WAIT_SOURCES;
      sourceWaitStart_.reset();
      return true;
    }

    uint8_t sourceCount = payload[16];
    A2_LOG_INFO(fmt("CUID#%" PRId64 " - ED2K found %u sources",
                    getCuid(), sourceCount));

    size_t expectedSize = 17 + static_cast<size_t>(sourceCount) * 6;
    if (payload.size() < expectedSize) {
      sourceCount = static_cast<uint8_t>(
          (payload.size() - 17) / 6);
    }

    for (size_t i = 0; i < sourceCount; ++i) {
      size_t off = 17 + i * 6;
      char ipStr[16];
      snprintf(ipStr, sizeof(ipStr), "%u.%u.%u.%u",
               payload[off], payload[off + 1],
               payload[off + 2], payload[off + 3]);
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

      // Skip duplicate sources
      bool dup = false;
      for (const auto& s : sources_) {
        if (s.addr == ipStr && s.port == port) {
          dup = true;
          break;
        }
      }
      if (dup) continue;

      PeerSource src;
      src.addr = ipStr;
      src.port = port;
      sources_.push_back(src);

      A2_LOG_INFO(fmt("CUID#%" PRId64 " - ED2K source %zu: %s:%u",
                      getCuid(), sources_.size(), ipStr, port));
    }

    if (sources_.empty()) {
      A2_LOG_INFO(fmt("CUID#%" PRId64 " - ED2K: no connectable sources,"
                      " will wait and retry", getCuid()));
      state_ = Ed2kState::SERVER_WAIT_SOURCES;
      sourceWaitStart_.reset();
      return true;
    }

    // Close server socket — peer phase will use its own socket.
    // Must disable event checks before closing to avoid stale registrations.
    disableReadCheckSocket();
    disableWriteCheckSocket();
    try { getSocket()->closeConnection(); } catch (...) {}

    currentSourceIndex_ = 0;
    state_ = Ed2kState::PEER_CONNECT;
    return true;
  }
  catch (RecoverableException& e) {
    A2_LOG_WARN(fmt("CUID#%" PRId64 " - ED2K server get sources error: %s,"
                    " trying next server", getCuid(), e.what()));
    disableReadCheckSocket();
    disableWriteCheckSocket();
    try { if (getSocket()) getSocket()->closeConnection(); } catch (...) {}
    currentServerIndex_++;
    state_ = Ed2kState::SERVER_CONNECT;
    return false;
  }
}

bool Ed2kDownloadCommand::serverWaitSources()
{
  // Wait for SOURCE_WAIT_SECONDS, then re-request sources from the server.
  auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
      sourceWaitStart_.difference()).count();

  if (elapsed < SOURCE_WAIT_SECONDS) {
    A2_LOG_DEBUG(fmt("CUID#%" PRId64 " - ED2K: waiting for sources (%lld/%ds)",
                     getCuid(), static_cast<long long>(elapsed),
                     SOURCE_WAIT_SECONDS));
    return false;
  }

  A2_LOG_INFO(fmt("CUID#%" PRId64 " - ED2K: retrying source request", getCuid()));

  // Reconnect to server and request sources again.
  try {
    if (getSocket() && getSocket()->isOpen()) {
      disableReadCheckSocket();
      disableWriteCheckSocket();
      getSocket()->closeConnection();
    }
  }
  catch (...) {}

  // Move to next server (or wrap around)
  currentServerIndex_++;
  if (currentServerIndex_ >= serverList_.size()) {
    currentServerIndex_ = 0;
    serverRound_++;
    if (serverRound_ > MAX_SERVER_ROUNDS) {
      A2_LOG_ERROR(fmt("CUID#%" PRId64 " - ED2K: exhausted all server rounds"
                       " while waiting for sources", getCuid()));
      state_ = Ed2kState::FAILURE;
      return false;
    }
  }

  // Reset for fresh server connection
  loginSent_ = false;
  sourcesRequested_ = false;
  sendBuffer_.clear();
  recvBuffer_.clear();

  state_ = Ed2kState::SERVER_CONNECT;
  return true;
}

// ============================================================================
// Peer phase
// ============================================================================

void Ed2kDownloadCommand::tryNextPeer()
{
  // Mark the current peer as failed (cooldown prevents immediate retry).
  // A transient failure keeps the peer in the pool (skipped while in
  // cooldown); a permanent one evicts it. This avoids the "delete peer →
  // re-find sources → oscillate" anti-pattern of naive implementations.
  if (currentSourceIndex_ < sources_.size()) {
    const auto& cur = sources_[currentSourceIndex_];
    markPeerFailed(cur.addr, cur.port);
  }

  // Clear stale protocol buffers — we're switching to a new peer
  sendBuffer_.clear();
  recvBuffer_.clear();

  // Advance past FAILED/EXPIRED sources. We do NOT clear the source list:
  // keeping failed entries lets the cooldown logic prevent immediate
  // retries, and they may become usable again after the cooldown window.
  currentSourceIndex_++;
  while (currentSourceIndex_ < sources_.size()) {
    const auto& s = sources_[currentSourceIndex_];
    if (s.state != SourceState::FAILED && s.state != SourceState::EXPIRED) {
      break;
    }
    // If the cooldown has expired, allow the peer to be retried.
    if (s.state == SourceState::FAILED &&
        !isPeerInCooldown(s.addr, s.port)) {
      break;
    }
    currentSourceIndex_++;
  }

  if (currentSourceIndex_ >= sources_.size()) {
    A2_LOG_INFO(fmt("CUID#%" PRId64 " - ED2K: exhausted all %zu peer sources,"
                    " reconnecting to server for fresh sources",
                    getCuid(), sources_.size()));
    // Don't clear sources — keep them for cooldown reference.
    // Reconnect to server for fresh sources.
    currentSourceIndex_ = 0;

    if (!reconnectServer()) {
      state_ = Ed2kState::FAILURE;
    }
    // state_ is set to SERVER_CONNECT by reconnectServer()
    return;
  }

  A2_LOG_INFO(fmt("CUID#%" PRId64 " - ED2K trying next peer source %zu/%zu",
                  getCuid(), currentSourceIndex_ + 1, sources_.size()));
  state_ = Ed2kState::PEER_CONNECT;
}

bool Ed2kDownloadCommand::reconnectServer()
{
  // Close any existing socket
  disableReadCheckSocket();
  disableWriteCheckSocket();
  try {
    if (getSocket() && getSocket()->isOpen()) {
      getSocket()->closeConnection();
    }
  }
  catch (...) {}

  // Move to next server
  currentServerIndex_++;
  if (currentServerIndex_ >= serverList_.size()) {
    currentServerIndex_ = 0;
    serverRound_++;
    if (serverRound_ > MAX_SERVER_ROUNDS) {
      A2_LOG_ERROR(fmt("CUID#%" PRId64 " - ED2K: exhausted all server rounds",
                       getCuid()));
      return false;
    }
  }

  A2_LOG_INFO(fmt("CUID#%" PRId64 " - ED2K: reconnecting to server"
                  " (round %d)", getCuid(), serverRound_));

  // Reset state for fresh server connection
  loginSent_ = false;
  sourcesRequested_ = false;
  sendBuffer_.clear();
  recvBuffer_.clear();

  state_ = Ed2kState::SERVER_CONNECT;
  return true;
}

// ============================================================================
// Source management helpers
// ============================================================================

void Ed2kDownloadCommand::markPeerFailed(const std::string& addr,
                                          uint16_t port, bool permanent)
{
  // Update the source's lifecycle state.
  for (auto& s : sources_) {
    if (s.addr == addr && s.port == port) {
      s.state = permanent ? SourceState::EXPIRED : SourceState::FAILED;
      s.lastActive.reset();
      break;
    }
  }

  // Permanent failures are evicted from the source pool entirely so
  // tryNextPeer()/peerConnect() never retry them. Transient failures
  // stay in the pool but are skipped while in cooldown.
  if (permanent) {
    sources_.erase(
        std::remove_if(sources_.begin(), sources_.end(),
                       [&addr, port](const PeerSource& s) {
                         return s.addr == addr && s.port == port;
                       }),
        sources_.end());
    // Keep currentSourceIndex_ in range.
    if (currentSourceIndex_ >= sources_.size() && !sources_.empty()) {
      currentSourceIndex_ = 0;
    }
  }

  // Record in failedPeers_ for cooldown tracking.
  for (auto& fp : failedPeers_) {
    if (fp.addr == addr && fp.port == port) {
      fp.failTime.reset();
      fp.permanent = permanent;
      return;
    }
  }
  FailedPeer fp;
  fp.addr = addr;
  fp.port = port;
  fp.failTime.reset();
  fp.permanent = permanent;
  failedPeers_.push_back(fp);

  // Prune expired entries to prevent unbounded growth.
  // Permanent entries are pruned immediately (already evicted from pool).
  auto now = global::wallclock();
  failedPeers_.erase(
      std::remove_if(failedPeers_.begin(), failedPeers_.end(),
                     [&now](const FailedPeer& p) {
                       return p.permanent ||
                              p.failTime.difference(now) >
                                  std::chrono::seconds(PEER_COOLDOWN_SECONDS);
                     }),
      failedPeers_.end());
}

bool Ed2kDownloadCommand::isPeerInCooldown(const std::string& addr,
                                            uint16_t port)
{
  auto now = global::wallclock();
  for (auto& fp : failedPeers_) {
    if (fp.addr == addr && fp.port == port) {
      if (fp.permanent) return true;
      if (fp.failTime.difference(now) <
          std::chrono::seconds(PEER_COOLDOWN_SECONDS)) {
        return true;
      }
      return false;
    }
  }
  return false;
}

void Ed2kDownloadCommand::addSource(const std::string& addr, uint16_t port)
{
  if (addr.empty() || port == 0) return;
  if (static_cast<int>(sources_.size()) >= maxSources_) return;

  // Check for duplicates
  for (const auto& s : sources_) {
    if (s.addr == addr && s.port == port) return;
  }

  // Skip peers in cooldown (or permanently failed)
  if (isPeerInCooldown(addr, port)) return;

  PeerSource ps;
  ps.addr = addr;
  ps.port = port;
  ps.state = SourceState::NEW;
  sources_.push_back(ps);
}

int Ed2kDownloadCommand::countActiveSources()
{
  int n = 0;
  for (const auto& s : sources_) {
    if (s.state == SourceState::CONNECTED ||
        s.state == SourceState::DOWNLOADING ||
        s.state == SourceState::QUEUED) {
      n++;
    }
  }
  return n;
}

int Ed2kDownloadCommand::getDynamicExchangeInterval()
{
  // Dynamic source-exchange frequency:
  //   few active sources  -> aggressive (60s) to find more
  //   many active sources -> relaxed (600s) to reduce load
  //   otherwise           -> user-configured default
  int active = countActiveSources();
  if (active < 5) {
    return 60;
  }
  if (active > 20) {
    return 600;
  }
  return sourceExchangeInterval_;
}

void Ed2kDownloadCommand::sendSourceExchangeRequest()
{
  std::vector<unsigned char> hashBytes = Ed2kHelper::hexToHash(fileHash_);
  if (hashBytes.size() != 16) return;

  std::vector<unsigned char> payload;
  payload.insert(payload.end(), hashBytes.begin(), hashBytes.end());
  payload.push_back(0);
  payload.push_back(0);

  queueMessage(ed2kmsg::SOURCES_REQUEST, payload.data(), payload.size());
  sourceExchangeSent_ = true;
  sourceExchangeTimer_.reset();

  A2_LOG_INFO(fmt("CUID#%" PRId64 " - ED2K: sent periodic source exchange",
                  getCuid()));
}

size_t Ed2kDownloadCommand::parseSourcesAnswer(
    const std::vector<unsigned char>& payload)
{
  if (payload.size() < 17) return 0;

  size_t count = payload[16];
  size_t expectedSize = 17 + count * 6;
  if (payload.size() < expectedSize) return 0;

  size_t added = 0;
  for (size_t i = 0; i < count; i++) {
    size_t offset = 17 + i * 6;
    uint32_t ip = static_cast<uint32_t>(payload[offset]) |
                  (static_cast<uint32_t>(payload[offset + 1]) << 8) |
                  (static_cast<uint32_t>(payload[offset + 2]) << 16) |
                  (static_cast<uint32_t>(payload[offset + 3]) << 24);
    uint16_t port = static_cast<uint16_t>(payload[offset + 4]) |
                    (static_cast<uint16_t>(payload[offset + 5]) << 8);
    if (ip == 0 || port == 0) continue;

    struct in_addr inAddr;
    inAddr.s_addr = htonl(ip);
    char ipStr[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &inAddr, ipStr, sizeof(ipStr));

    size_t before = sources_.size();
    addSource(ipStr, port);
    if (sources_.size() > before) added++;
  }

  if (added > 0) {
    A2_LOG_INFO(fmt("CUID#%" PRId64
                    " - ED2K: source exchange added %zu sources (total %zu)",
                    getCuid(), added, sources_.size()));
  }
  return added;
}

void Ed2kDownloadCommand::checkServerSourceRefresh()
{
  if (!serverSourceEnabled_) return;
  if (static_cast<int>(sources_.size()) >= maxSources_) return;

  // Only refresh from the server when active sources are scarce.
  // Popular files with plenty of sources don't benefit from repeated
  // server queries — it just wastes server budget.
  if (countActiveSources() >= 5) return;

  if (serverSourceRefreshTimer_.difference() >
      std::chrono::seconds(SERVER_SOURCE_REFRESH_SECONDS)) {
    A2_LOG_INFO(fmt("CUID#%" PRId64
                    " - ED2K: periodic server source refresh triggered"
                    " (active sources: %d)",
                    getCuid(), countActiveSources()));
    serverSourceRefreshTimer_.reset();
    // Re-ask the server for sources by transitioning back to
    // SERVER_CONNECT. The download will resume from current offset
    // after fresh sources are obtained.
    loginSent_ = false;
    sourcesRequested_ = false;
    sendBuffer_.clear();
    recvBuffer_.clear();
    try {
      if (getSocket() && getSocket()->isOpen()) {
        getSocket()->closeConnection();
      }
    }
    catch (...) {}
    disableReadCheckSocket();
    disableWriteCheckSocket();
    state_ = Ed2kState::SERVER_CONNECT;
  }
}

// ============================================================================
// KAD (Kademlia DHT) source lookup via UDP
// ============================================================================

void Ed2kDownloadCommand::initKad()
{
  // Parse KAD bootstrap nodes from user config, or use defaults.
  std::string nodesConfig;
  auto opt = getOption();
  if (opt) {
    nodesConfig = opt->get(PREF_ED2K_KAD_BOOTSTRAP_NODES);
  }

  std::vector<Ed2kServerEntry> nodes;
  if (!nodesConfig.empty()) {
    Ed2kHelper::parseKadBootstrapNodes(nodesConfig, nodes);
  }
  else {
    Ed2kHelper::getDefaultKadBootstrapNodes(nodes);
  }

  for (const auto& n : nodes) {
    kadNodes_.push_back({n.addr, n.port});
  }

  A2_LOG_INFO(fmt("CUID#%" PRId64 " - ED2K: KAD initialized with %zu nodes",
                  getCuid(), kadNodes_.size()));

  // Create UDP socket for KAD communication.
  try {
    kadSocket_ = std::make_shared<SocketCore>(SOCK_DGRAM);
    kadSocket_->bindWithFamily(0, AF_INET);
    kadSocket_->setNonBlockingMode();
    kadRefreshTimer_.reset();
    kadBootstrapSent_ = false;
    kadState_ = KadState::BOOTSTRAP;
  }
  catch (RecoverableException& e) {
    A2_LOG_WARN(fmt("CUID#%" PRId64 " - ED2K: KAD socket init failed: %s",
                    getCuid(), e.what()));
    kadSocket_.reset();
  }
}

void Ed2kDownloadCommand::kadStateMachine()
{
  if (!kadEnabled_ || !kadSocket_ || kadNodes_.empty()) return;

  // Always drain any pending UDP response first (non-blocking).
  // Receiving a response implies the bootstrap/find succeeded, so we
  // advance the state machine accordingly.
  bool gotResponse = kadProcessResponse();

  switch (kadState_) {
  case KadState::BOOTSTRAP: {
    if (!kadBootstrapSent_) {
      kadBootstrap();
      kadRefreshTimer_.reset();
    }
    else if (kadRefreshTimer_.difference() > std::chrono::seconds(30)) {
      // Bootstrap timed out — try the next node.
      currentKadNodeIndex_++;
      kadBootstrapSent_ = false;
      if (currentKadNodeIndex_ >= kadNodes_.size()) {
        A2_LOG_WARN(fmt("CUID#%" PRId64 " - ED2K: KAD bootstrap exhausted"
                        " all nodes", getCuid()));
        kadState_ = KadState::COMPLETE;
        kadRefreshTimer_.reset();
      }
    }
    // Any response means we're on the network — proceed to search.
    if (gotResponse) {
      A2_LOG_INFO(fmt("CUID#%" PRId64 " - ED2K: KAD bootstrap complete,"
                      " entering READY", getCuid()));
      kadState_ = KadState::READY;
      kadRefreshTimer_.reset();
    }
    break;
  }

  case KadState::READY: {
    kadFindSource();
    kadState_ = KadState::SEARCHING;
    kadRefreshTimer_.reset();
    break;
  }

  case KadState::SEARCHING: {
    // Give the search a short window to collect direct responses.
    if (gotResponse) {
      kadRefreshTimer_.reset(); // extend window on activity
    }
    if (kadRefreshTimer_.difference() > std::chrono::seconds(10)) {
      kadState_ = KadState::WAIT_RESPONSE;
      kadRefreshTimer_.reset();
    }
    break;
  }

  case KadState::WAIT_RESPONSE: {
    if (gotResponse) {
      kadRefreshTimer_.reset();
    }
    if (kadRefreshTimer_.difference() > std::chrono::seconds(30)) {
      // No more responses — round complete.
      kadState_ = KadState::COMPLETE;
      kadRefreshTimer_.reset();
    }
    break;
  }

  case KadState::COMPLETE: {
    // Wait for the refresh interval before starting another round.
    // Also re-trigger if active sources dropped and we still have nodes.
    if (kadRefreshTimer_.difference() >
            std::chrono::seconds(KAD_REFRESH_SECONDS) ||
        (countActiveSources() < 5 &&
         kadRefreshTimer_.difference() > std::chrono::seconds(60))) {
      // Rotate to the next bootstrap node for diversity.
      currentKadNodeIndex_++;
      if (currentKadNodeIndex_ >= kadNodes_.size()) {
        currentKadNodeIndex_ = 0;
      }
      kadBootstrapSent_ = false;
      kadState_ = KadState::READY;
      kadRefreshTimer_.reset();
    }
    break;
  }
  }
}

void Ed2kDownloadCommand::kadBootstrap()
{
  if (!kadSocket_ || kadNodes_.empty()) return;

  // Rotate to next bootstrap node
  const auto& node = kadNodes_[currentKadNodeIndex_ % kadNodes_.size()];

  // KAD2_BOOTSTRAP_REQ:
  // [1 byte] 0xE3 (protocol)
  // [1 byte] opcode (KAD2_BOOTSTRAP_REQ = 0x2B in eMule)
  // [16 bytes] client ID (random, used for node identification)
  // [16 bytes] target ID (our node ID, derived from user hash)
  std::vector<unsigned char> packet;
  packet.push_back(0xE3);
  packet.push_back(0x2B); // KAD2_BOOTSTRAP_REQ
  // Client ID — use our user hash (reversed for KAD)
  std::vector<unsigned char> hashBytes = Ed2kHelper::hexToHash(fileHash_);
  if (hashBytes.size() == 16) {
    packet.insert(packet.end(), hashBytes.begin(), hashBytes.end());
  }
  else {
    // Fallback: zeros
    packet.insert(packet.end(), 16, 0);
  }
  // Target ID — same as client ID for bootstrap
  packet.insert(packet.end(), 16, 0);

  try {
    kadSocket_->writeData(packet.data(), packet.size(),
                           node.first, node.second);
    kadBootstrapSent_ = true;
    A2_LOG_INFO(fmt("CUID#%" PRId64 " - ED2K: KAD bootstrap sent to %s:%u",
                    getCuid(), node.first.c_str(), node.second));
  }
  catch (RecoverableException& e) {
    A2_LOG_DEBUG(fmt("CUID#%" PRId64 " - ED2K: KAD bootstrap failed: %s",
                     getCuid(), e.what()));
    currentKadNodeIndex_++;
  }
}

void Ed2kDownloadCommand::kadFindSource()
{
  if (!kadSocket_ || kadNodes_.empty()) return;

  const auto& node = kadNodes_[currentKadNodeIndex_ % kadNodes_.size()];

  // KAD2_REQ: search for file sources by file hash.
  // [1 byte]  0xE3 (protocol)
  // [1 byte]  opcode (KAD2_REQ = 0x2A in eMule, simplified)
  // [16 bytes] file hash (MD4) — the file we're looking for
  // [1 byte]  search type (0 = FIND_SOURCE)
  std::vector<unsigned char> packet;
  packet.push_back(0xE3);
  packet.push_back(0x2A); // KAD2_REQ (simplified)
  std::vector<unsigned char> hashBytes = Ed2kHelper::hexToHash(fileHash_);
  if (hashBytes.size() != 16) return;
  packet.insert(packet.end(), hashBytes.begin(), hashBytes.end());
  packet.push_back(0x00); // FIND_SOURCE

  try {
    kadSocket_->writeData(packet.data(), packet.size(),
                           node.first, node.second);
    A2_LOG_INFO(fmt("CUID#%" PRId64 " - ED2K: KAD find-source sent to %s:%u"
                    " for hash %s",
                    getCuid(), node.first.c_str(), node.second,
                    fileHash_.c_str()));
  }
  catch (RecoverableException& e) {
    A2_LOG_DEBUG(fmt("CUID#%" PRId64 " - ED2K: KAD find-source failed: %s",
                     getCuid(), e.what()));
    currentKadNodeIndex_++;
  }
}

bool Ed2kDownloadCommand::kadProcessResponse()
{
  if (!kadSocket_) return false;

  unsigned char buf[1024];
  Endpoint sender;

  try {
    ssize_t n = kadSocket_->readDataFrom(buf, sizeof(buf), sender);
    if (n <= 0) return false;

    A2_LOG_DEBUG(fmt("CUID#%" PRId64 " - ED2K: KAD response %zd bytes from %s:%u",
                     getCuid(), n, sender.addr.c_str(), sender.port));

    // Minimal KAD response parsing:
    // [1 byte]  protocol (0xE3)
    // [1 byte]  opcode
    // [rest]    payload
    if (n < 2 || buf[0] != 0xE3) return false;

    unsigned char opcode = buf[1];
    // KAD2_REQ_RESID (0x4B) or KAD2_HELLO_RES (0x4C) responses may
    // contain source information.
    // For a simplified implementation, we look for KAD2_REQ_RESID
    // which contains peer contact info.
    if (opcode == 0x4B && n >= 2 + 6) {
      // Parse sources from the response.
      // Format (simplified): [16 bytes file_hash][1 byte count][count × 6 bytes]
      // The actual KAD response format is more complex, but we try to
      // extract any [IP:port] pairs we can find.
      size_t offset = 2;
      // Skip file hash if present
      if (n >= offset + 16) offset += 16;
      // Try to read source count
      if (n >= offset + 1) {
        size_t count = buf[offset++];
        for (size_t i = 0; i < count && offset + 6 <= static_cast<size_t>(n); i++) {
          uint32_t ip = static_cast<uint32_t>(buf[offset]) |
                        (static_cast<uint32_t>(buf[offset + 1]) << 8) |
                        (static_cast<uint32_t>(buf[offset + 2]) << 16) |
                        (static_cast<uint32_t>(buf[offset + 3]) << 24);
          uint16_t port = static_cast<uint16_t>(buf[offset + 4]) |
                          (static_cast<uint16_t>(buf[offset + 5]) << 8);
          offset += 6;

          if (ip == 0 || port == 0) continue;

          struct in_addr inAddr;
          inAddr.s_addr = htonl(ip);
          char ipStr[INET_ADDRSTRLEN];
          inet_ntop(AF_INET, &inAddr, ipStr, sizeof(ipStr));

          size_t before = sources_.size();
          addSource(ipStr, port);
          if (sources_.size() > before) {
            A2_LOG_INFO(fmt("CUID#%" PRId64
                            " - ED2K: KAD found source %s:%u",
                            getCuid(), ipStr, port));
          }
        }
      }
    }
    return true;
  }
  catch (RecoverableException& e) {
    // EAGAIN or other error — non-fatal
    return false;
  }
}

bool Ed2kDownloadCommand::peerConnect()
{
  if (currentSourceIndex_ >= sources_.size()) {
    tryNextPeer();
    return false;
  }

  PeerSource& src = sources_[currentSourceIndex_];

  // Skip sources that are in cooldown or permanently expired.
  if (src.state == SourceState::FAILED || src.state == SourceState::EXPIRED) {
    currentSourceIndex_++;
    addCommandSelf();
    return false;
  }

  src.state = SourceState::CONNECTING;
  src.lastActive.reset();

  A2_LOG_INFO(fmt("CUID#%" PRId64 " - ED2K connecting to peer %s:%u",
                  getCuid(), src.addr.c_str(), src.port));

  // Close old socket and clear ALL protocol state.
  // This is critical: when switching between sockets (server→peer or
  // peer→peer), all protocol state (send/recv buffers, flags) must be
  // reset to prevent stream corruption.
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

  // Clear protocol buffers
  sendBuffer_.clear();
  recvBuffer_.clear();

  // Reset peer-phase flags
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

  // Non-blocking connect initiated — transition to wait state.
  // The socket will become writable when connected (or on error).
  state_ = Ed2kState::PEER_WAIT_CONNECT;
  return false;
}

bool Ed2kDownloadCommand::peerWaitConnect()
{
  // Check if the non-blocking connect() has completed.
  // isWritable(0) uses poll() with 0 timeout — returns true immediately
  // if the socket is writable (connected or error).
  if (!getSocket()->isWritable(0)) {
    // Connection still in progress — wait more
    return false;
  }

  // Socket is writable — check for connection errors via SO_ERROR.
  // Same pattern as AbstractCommand::checkIfConnectionEstablished().
  std::string err = getSocket()->getSocketError();
  if (!err.empty()) {
    A2_LOG_WARN(fmt("CUID#%" PRId64 " - ED2K peer connection failed: %s"
                    " (peer %s:%u)",
                    getCuid(), err.c_str(),
                    sources_[currentSourceIndex_].addr.c_str(),
                    sources_[currentSourceIndex_].port));
    tryNextPeer();
    return false;
  }

  A2_LOG_INFO(fmt("CUID#%" PRId64 " - ED2K peer connection established (%s:%u)",
                  getCuid(),
                  sources_[currentSourceIndex_].addr.c_str(),
                  sources_[currentSourceIndex_].port));

  // Connection established — reset timer and proceed
  getCheckPoint().reset();
  return true;
}

bool Ed2kDownloadCommand::peerHandshake()
{
  try {
    // Send OP_HELLO (once)
    if (!helloSent_) {
      // OP_HELLO payload (eDonkey tag-based format):
      //   [16 bytes] user_hash (MD4)
      //   [4 bytes]  user_id (0)
      //   [2 bytes]  tcp_port (4662, LE)
      //   [4 bytes]  server_ip (LE — first octet in byte 0)
      //   [2 bytes]  server_port (LE)
      //   [4 bytes]  tag_count (LE)
      //   [tags...]  tag list
      //
      // Tags:
      //   CT_NAME (0x01)     — username string
      //   CT_VERSION (0x11)  — client version int32
      std::vector<unsigned char> payload;
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
      // Server IP — store as 4 LE bytes (first octet in byte 0).
      // inet_addr returns network byte order (big-endian); on LE hosts
      // the in-memory bytes are already [octet0, octet1, octet2, octet3].
      // We copy raw bytes to be platform-independent.
      if (!serverAddr_.empty()) {
        struct in_addr inAddr;
        if (inet_pton(AF_INET, serverAddr_.c_str(), &inAddr) == 1) {
          const unsigned char* ipBytes =
              reinterpret_cast<const unsigned char*>(&inAddr.s_addr);
          payload.insert(payload.end(), ipBytes, ipBytes + 4);
        }
        else {
          // Invalid IP — send zeros
          payload.push_back(0); payload.push_back(0);
          payload.push_back(0); payload.push_back(0);
        }
      }
      else {
        payload.push_back(0); payload.push_back(0);
        payload.push_back(0); payload.push_back(0);
      }
      // Server port (LE)
      payload.push_back(static_cast<unsigned char>(serverPort_));
      payload.push_back(static_cast<unsigned char>(serverPort_ >> 8));
      // Tag count = 2 (LE uint32)
      payload.push_back(2); payload.push_back(0);
      payload.push_back(0); payload.push_back(0);
      // Tag 1: CT_NAME = "eMule"
      append_string_tag(payload, ed2ktag::CT_NAME, "eMule");
      // Tag 2: CT_VERSION = 0x3C (eMule 0.60)
      append_int32_tag(payload, ed2ktag::CT_VERSION, 0x3C);

      queueMessage(ed2kmsg::HELLO, payload.data(), payload.size());
      helloSent_ = true;

      A2_LOG_DEBUG(fmt("CUID#%" PRId64 " - ED2K sending peer hello",
                       getCuid()));

      if (!flushSendBuffer()) {
        if (connectionError_) {
          // Socket is dead — let execute() handle it
          return false;
        }
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

    // Skip queue ranking notifications
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

    // Handshake complete — peer is now connected but not yet downloading.
    if (currentSourceIndex_ < sources_.size()) {
      sources_[currentSourceIndex_].state = SourceState::CONNECTED;
      sources_[currentSourceIndex_].lastActive.reset();
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

bool Ed2kDownloadCommand::peerSourceExchange()
{
  // Source Exchange: ask the connected peer for additional sources.
  // Best-effort — if the peer doesn't respond or doesn't support it,
  // we just proceed to upload request.

  try {
    if (!sourceExchangeSent_) {
      sendSourceExchangeRequest();
      if (!flushSendBuffer()) {
        if (connectionError_) return false;
        setWriteCheckSocket(getSocket());
        return false;
      }
    }

    // Try to receive OP_SOURCESANSWER (non-blocking)
    unsigned char msgType = 0;
    std::vector<unsigned char> payload;
    if (!tryReceiveMessage(msgType, payload)) {
      // No response yet — wait a bit (max 5 seconds) before proceeding
      if (sourceExchangeTimer_.difference(global::wallclock()) >
          std::chrono::seconds(5)) {
        A2_LOG_INFO(fmt("CUID#%" PRId64
                        " - ED2K: source exchange timed out, proceeding",
                        getCuid()));
        return true;
      }
      return false;
    }

    if (msgType == ed2kmsg::SOURCES_ANSWER) {
      parseSourcesAnswer(payload);
    }
    // Ignore other message types during source exchange

    return true;
  }
  catch (RecoverableException& e) {
    A2_LOG_INFO(fmt("CUID#%" PRId64 " - ED2K source exchange error: %s",
                    getCuid(), e.what()));
    return true;
  }
}

bool Ed2kDownloadCommand::peerStartUpload()
{
  try {
    // Send OP_START_UPLOAD_REQ (once)
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
        if (connectionError_) {
          return false;
        }
        setWriteCheckSocket(getSocket());
        return false;
      }
    }

    // Receive OP_ACCEPT_UPLOAD_REQ.
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
        // Upload slot granted — we're now actively downloading.
        if (currentSourceIndex_ < sources_.size()) {
          sources_[currentSourceIndex_].state = SourceState::DOWNLOADING;
          sources_[currentSourceIndex_].queuePosition = -1;
        }
        return true;
      }

      if (msgType == ed2kmsg::QUEUE_POSITION) {
        // We're in the peer's upload queue. Parse the queue rank so the
        // source manager can distinguish "queued" from "failed".
        // OP_QUEUERANKING payload: [16 bytes hash][4 bytes rank LE]
        int queueRank = -1;
        if (payload.size() >= 20) {
          queueRank = static_cast<int>(payload[16]) |
                      (static_cast<int>(payload[17]) << 8) |
                      (static_cast<int>(payload[18]) << 16) |
                      (static_cast<int>(payload[19]) << 24);
        }
        if (currentSourceIndex_ < sources_.size()) {
          sources_[currentSourceIndex_].state = SourceState::QUEUED;
          sources_[currentSourceIndex_].queuePosition = queueRank;
        }
        A2_LOG_DEBUG(fmt("CUID#%" PRId64 " - ED2K queued for upload slot"
                         " (rank=%d)", getCuid(), queueRank));
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
    // --- Periodic source discovery during download ---
    // These checks run on every execute() call and are non-blocking.
    // Together they form the source-discovery loop:
    //   ├── Source Exchange (dynamic interval)
    //   ├── KAD Lookup (state machine)
    //   └── Server Refresh (conditional on active source count)

    // 1. Periodic source exchange with current peer.
    //    Interval is dynamic: aggressive when sources are scarce, relaxed
    //    when plentiful (see getDynamicExchangeInterval()).
    if (sourceExchangeEnabled_ &&
        sourceExchangeTimer_.difference() >
            std::chrono::seconds(getDynamicExchangeInterval())) {
      A2_LOG_INFO(fmt("CUID#%" PRId64
                      " - ED2K: periodic source exchange during download"
                      " (interval=%ds, active=%d)",
                      getCuid(), getDynamicExchangeInterval(),
                      countActiveSources()));
      sendSourceExchangeRequest();
      // Flush the request — don't block if EAGAIN
      flushSendBuffer();
    }

    // 2. KAD source lookup — driven by the KAD state machine.
    //    kadStateMachine() drains responses and advances:
    //    BOOTSTRAP → READY → SEARCHING → WAIT_RESPONSE → COMPLETE.
    if (kadEnabled_ && kadSocket_) {
      kadStateMachine();
    }

    // 3. Periodic server source refresh
    checkServerSourceRefresh();
    // If server refresh triggered, state_ changed — return to re-enter
    if (state_ != Ed2kState::PEER_DOWNLOAD) {
      addCommandSelf();
      return false;
    }

    // Completion check: either sequential cursor reached the end, or all
    // parts (when tracked) are complete. The parts-based check handles
    // out-of-order downloads where downloadOffset_ may have jumped.
    bool allDone = downloadOffset_ >= static_cast<int64_t>(fileSize_);
    if (!allDone && !parts_.empty()) {
      allDone = true;
      for (const auto& p : parts_) {
        if (!p.completed) { allDone = false; break; }
      }
    }
    while (!allDone) {
      switch (downloadSubState_) {
      case DownloadSubState::REQUEST_PARTS: {
        // Part Availability Manager: if the current peer's part bitmap is
        // known and downloadOffset_ points at a part the peer does NOT
        // have, jump to the rarest available incomplete part. This avoids
        // requesting data the peer can't provide and spreads requests
        // across regions instead of everyone hammering 0-1GB.
        if (!parts_.empty() && currentSourceIndex_ < sources_.size()) {
          const auto& src = sources_[currentSourceIndex_];
          if (!src.availableParts.empty()) {
            size_t curPart = partIndexForOffset(downloadOffset_);
            if (curPart < src.availableParts.size() &&
                !src.availableParts[curPart] &&
                curPart < parts_.size() && !parts_[curPart].completed) {
              int best = findBestPartToDownload(currentSourceIndex_);
              if (best >= 0) {
                A2_LOG_INFO(fmt("CUID#%" PRId64 " - ED2K: jumping to part %d"
                                " (offset %" PRId64 ") — current part not"
                                " available from this peer",
                                getCuid(), best, parts_[best].offset));
                downloadOffset_ = parts_[best].offset;
              }
            }
            // Mark the part we're about to request as in-progress.
            size_t reqPart = partIndexForOffset(downloadOffset_);
            if (reqPart < parts_.size()) {
              parts_[reqPart].downloading = true;
              parts_[reqPart].lastRequested.reset();
            }
          }
        }

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
          if (connectionError_) {
            return false;
          }
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

          // Part Availability Manager: record that the current source
          // actually has this part (proof-by-transfer), and mark the
          // part complete if the written data reaches its end.
          if (!parts_.empty() && currentSourceIndex_ < sources_.size()) {
            size_t pidx = partIndexForOffset(static_cast<int64_t>(dataStart));
            if (pidx < parts_.size()) {
              // Mark part available for this source.
              auto& src = sources_[currentSourceIndex_];
              if (src.availableParts.empty()) {
                src.availableParts.assign(parts_.size(), false);
              }
              if (pidx < src.availableParts.size()) {
                src.availableParts[pidx] = true;
              }
              auto& srcs = parts_[pidx].sources;
              if (std::find(srcs.begin(), srcs.end(), currentSourceIndex_) ==
                  srcs.end()) {
                srcs.push_back(currentSourceIndex_);
              }
              markPartCompleted(static_cast<int64_t>(dataStart),
                                static_cast<int64_t>(expectedDataLen));
            }
          }

          updateProgress();

          downloadSubState_ = DownloadSubState::REQUEST_PARTS;

          // Recompute completion: sequential cursor OR all parts done.
          allDone = downloadOffset_ >= static_cast<int64_t>(fileSize_);
          if (!allDone && !parts_.empty()) {
            allDone = true;
            for (const auto& p : parts_) {
              if (!p.completed) { allDone = false; break; }
            }
          }
          break;
        }

        if (msgType == ed2kmsg::END_UPLOAD_REQ) {
          A2_LOG_INFO(fmt("CUID#%" PRId64 " - ED2K peer ended upload,"
                          " trying next peer", getCuid()));
          tryNextPeer();
          return false;
        }

        // Handle async source exchange answer during download.
        // Peers may send OP_SOURCESANSWER unsolicited or in response to
        // our periodic OP_SOURCESREQUEST.
        if (msgType == ed2kmsg::SOURCES_ANSWER) {
          parseSourcesAnswer(payload);
          // Stay in RECEIVING_DATA — the actual data block will come next.
          break;
        }

        A2_LOG_DEBUG(fmt("CUID#%" PRId64 " - ED2K skipping message 0x%02x"
                         " during download",
                         getCuid(), msgType));
        break;
      }
      } // switch (downloadSubState_)
    } // while (!allDone)

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
    if (!dc || dc->getPieceLength() == 0) {
      return;
    }

    // Only call markPiecesDone() when downloadedLength_ has advanced past
    // a piece boundary to avoid duplicate Piece entries.
    size_t pieceLen = dc->getPieceLength();
    size_t lastPiece = static_cast<size_t>(lastMarkedLength_ / pieceLen);
    size_t curPiece = static_cast<size_t>(downloadedLength_ / pieceLen);

    if (curPiece > lastPiece) {
      ps->markPiecesDone(downloadedLength_);
      lastMarkedLength_ = downloadedLength_;
    }
  }
  catch (RecoverableException& e) {
    A2_LOG_DEBUG(fmt("CUID#%" PRId64 " - ED2K: updateProgress failed: %s",
                     getCuid(), e.what()));
  }
}

// ============================================================================
// Part Availability Manager
//
// ED2K divides a file into 9.5MB PARTs. Each peer typically only has a
// subset of parts (especially for large/incomplete downloads). To avoid
// every connection requesting the same region (e.g. everyone hammering
// 0-1GB), we track per-part availability across known sources and
// schedule the rarest incomplete part first.
//
// Availability is learned incrementally:
//   - When a peer successfully sends OP_SENDING_PART for a part, we mark
//     that part as available for that source (proof-by-transfer).
//   - When a source's part bitmap is learned via OP_FILESTATUS, it is
//     merged in via updatePartAvailability().
// ============================================================================

void Ed2kDownloadCommand::initParts()
{
  parts_.clear();
  if (partSize_ <= 0 || fileSize_ == 0) return;

  int64_t remaining = static_cast<int64_t>(fileSize_);
  int64_t offset = 0;
  while (remaining > 0) {
    PartInfo p;
    p.offset = offset;
    p.length = std::min<int64_t>(partSize_, remaining);
    p.completed = false;
    p.downloading = false;
    parts_.push_back(p);
    offset += partSize_;
    remaining -= partSize_;
  }

  // Mark parts already completed (resuming from a partial download).
  auto ps = getRequestGroup()->getPieceStorage();
  if (ps) {
    int64_t completed = ps->getCompletedLength();
    for (auto& p : parts_) {
      if (p.offset + p.length <= completed) {
        p.completed = true;
      }
    }
  }

  A2_LOG_INFO(fmt("CUID#%" PRId64 " - ED2K: Part Availability Manager"
                  " initialized with %zu parts (partSize=%" PRId64 ")",
                  getCuid(), parts_.size(), partSize_));
}

void Ed2kDownloadCommand::markPartCompleted(int64_t offset, int64_t length)
{
  if (parts_.empty()) return;
  size_t idx = partIndexForOffset(offset);
  if (idx >= parts_.size()) return;

  // A part is complete when the written data reaches its end.
  if (offset + length >= parts_[idx].offset + parts_[idx].length) {
    parts_[idx].completed = true;
    parts_[idx].downloading = false;
  }
}

void Ed2kDownloadCommand::updatePartAvailability(
    size_t sourceIndex, const std::vector<bool>& partBitmap)
{
  if (sourceIndex >= sources_.size() || parts_.empty()) return;

  // Resize the source's bitmap if needed.
  auto& src = sources_[sourceIndex];
  // A partial bitmap describes only the leading parts; the merge loop
  // below is bounded by min(availableParts, parts_) so it's handled.
  src.availableParts = partBitmap;
  if (src.availableParts.size() > parts_.size()) {
    src.availableParts.resize(parts_.size());
  }

  // Merge into the parts_ source lists.
  for (size_t i = 0; i < src.availableParts.size() && i < parts_.size(); i++) {
    if (src.availableParts[i]) {
      // Avoid duplicate entries.
      auto& srcs = parts_[i].sources;
      if (std::find(srcs.begin(), srcs.end(), sourceIndex) == srcs.end()) {
        srcs.push_back(sourceIndex);
      }
    }
  }

  A2_LOG_DEBUG(fmt("CUID#%" PRId64 " - ED2K: updated part availability for"
                   " source %zu (%zu parts)",
                   getCuid(), sourceIndex, src.availableParts.size()));
}

size_t Ed2kDownloadCommand::partIndexForOffset(int64_t offset)
{
  if (partSize_ <= 0) return 0;
  return static_cast<size_t>(offset / partSize_);
}

int Ed2kDownloadCommand::findBestPartToDownload(size_t sourceIndex)
{
  if (parts_.empty()) return -1;
  if (sourceIndex >= sources_.size()) return -1;

  const auto& src = sources_[sourceIndex];
  // An empty bitmap means "availability unknown" — fall back to sequential.
  bool hasBitmap = !src.availableParts.empty();

  // Collect candidate parts: incomplete, not currently downloading, and
  // (if we have a bitmap) owned by this source.
  std::vector<int> candidates;
  for (size_t i = 0; i < parts_.size(); i++) {
    if (parts_[i].completed || parts_[i].downloading) continue;
    if (hasBitmap && i < src.availableParts.size() && !src.availableParts[i]) {
      continue;
    }
    candidates.push_back(static_cast<int>(i));
  }

  if (candidates.empty()) return -1;

  // Rarest-first: sort by the number of known sources (ascending).
  // This spreads load across parts and avoids creating "holes" where a
  // part only one peer has disappears before we fetch it.
  std::sort(candidates.begin(), candidates.end(),
            [this](int a, int b) {
              return parts_[a].sources.size() < parts_[b].sources.size();
            });

  // Among the rarest, prefer parts not requested recently to avoid
  // hammering the same region across peer switches.
  auto now = global::wallclock();
  for (int idx : candidates) {
    if (parts_[idx].lastRequested.difference(now) >
        std::chrono::seconds(60)) {
      return idx;
    }
  }

  return candidates[0];
}

} // namespace aria2
