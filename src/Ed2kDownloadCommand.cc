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

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <initializer_list>
#include <random>
#include <vector>

#include "Request.h"
#include "SocketCore.h"
#include "DownloadEngine.h"
#include "RequestGroup.h"
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
#include <cstdint>
#include "wallclock.h"
#include "A2STR.h"
#include "Ed2kHelper.h"
#include "error_code.h"
#include "a2netcompat.h"

namespace aria2 {

// ============================================================================
// Wire constants (verified against eMule opcodes.h)
// ============================================================================
static const int64_t ED2K_BLOCK_SIZE = 184320; // 180 KiB standard block
static const size_t ED2K_HEADER_LEN = 4;
static const size_t ED2K_MAX_MSG_SIZE = 16 * 1024 * 1024;

// Protocol bytes (first byte after the 4-byte length).
static const unsigned char ED2K_PROT_EDONKEY = 0xE3;
static const unsigned char ED2K_PROT_EMULE = 0xC5;
static const unsigned char ED2K_PROT_PACKED = 0xD4; // zlib compressed — drop
static const unsigned char KAD2_PROT = 0xE4;

// How long a peer may go without delivering a block before we switch peers.
static const int PEER_STALL_SECONDS = 60;

namespace ed2kop {
// client <-> server (0xE3)
constexpr unsigned char LOGIN_REQUEST = 0x01;
constexpr unsigned char SERVER_MESSAGE = 0x38;
constexpr unsigned char ID_CHANGE = 0x40;
constexpr unsigned char SERVER_IDENT = 0x41;
constexpr unsigned char GET_SOURCES = 0x19;
constexpr unsigned char FOUND_SOURCES = 0x42;

// client <-> client (0xE3)
constexpr unsigned char HELLO = 0x01;
constexpr unsigned char HELLO_ANSWER = 0x4C;
constexpr unsigned char REQUEST_FILENAME = 0x58;
constexpr unsigned char REQ_FILENAME_ANSWER = 0x59;
constexpr unsigned char FILE_REQ_ANS_NO_FIL = 0x48;
constexpr unsigned char SET_REQ_FILE_ID = 0x4F;
constexpr unsigned char FILE_STATUS = 0x50;
constexpr unsigned char START_UPLOAD_REQ = 0x54;
constexpr unsigned char ACCEPT_UPLOAD_REQ = 0x55;
constexpr unsigned char CANCEL_TRANSFER = 0x56;
constexpr unsigned char END_OF_DOWNLOAD = 0x49;
constexpr unsigned char QUEUE_RANK = 0x5C;
constexpr unsigned char REQUEST_PARTS = 0x47;
constexpr unsigned char SENDING_PART = 0x46;
constexpr unsigned char SENDING_PART_I64 = 0xA2;
constexpr unsigned char REQUEST_PARTS_I64 = 0xA3;

// eMule extended (0xC5)
constexpr unsigned char EMULE_INFO = 0x01;
constexpr unsigned char EMULE_INFO_ANSWER = 0x02;
constexpr unsigned char QUEUE_RANKING = 0x60;
constexpr unsigned char REQUEST_SOURCES = 0x81;
constexpr unsigned char ANSWER_SOURCES = 0x82;
constexpr unsigned char ANSWER_SOURCES2 = 0x84;
} // namespace ed2kop

namespace kad2op {
constexpr unsigned char BOOTSTRAP_REQ = 0x01;
constexpr unsigned char BOOTSTRAP_RES = 0x09;
constexpr unsigned char HELLO_REQ = 0x11;
constexpr unsigned char HELLO_RES = 0x19;
constexpr unsigned char SEARCH_SOURCE_REQ = 0x34;
constexpr unsigned char SEARCH_RES = 0x3B;
} // namespace kad2op

// ED2K tag encoding (eMule CTag::WriteTagToFile, "new style" named tags):
//   [1 byte type | 0x80][1 byte numeric name id][value]
// Tag base types.
namespace ed2ktag {
constexpr unsigned char TYPE_STRING = 0x02;
constexpr unsigned char TYPE_UINT32 = 0x03;

// Client tag ids (CT_*).
constexpr unsigned char CT_NAME = 0x01;
constexpr unsigned char CT_PORT = 0x0F;
constexpr unsigned char CT_VERSION = 0x11;
constexpr unsigned char CT_SERVER_FLAGS = 0x20;

// eMule extended tag ids (ET_*, used in OP_EMULEINFO).
constexpr unsigned char ET_COMPRESSION = 0x20;
constexpr unsigned char ET_SOURCEEXCHANGE = 0x23;
constexpr unsigned char ET_EXTENDEDREQUEST = 0x25;
constexpr unsigned char ET_FEATURES = 0x27;
} // namespace ed2ktag

// ============================================================================
// Little-endian / hex helpers
// ============================================================================
namespace {

void appendLe16(std::vector<unsigned char>& out, uint16_t v)
{
  out.push_back(static_cast<unsigned char>(v));
  out.push_back(static_cast<unsigned char>(v >> 8));
}

void appendLe32(std::vector<unsigned char>& out, uint32_t v)
{
  out.push_back(static_cast<unsigned char>(v));
  out.push_back(static_cast<unsigned char>(v >> 8));
  out.push_back(static_cast<unsigned char>(v >> 16));
  out.push_back(static_cast<unsigned char>(v >> 24));
}

void appendLe64(std::vector<unsigned char>& out, uint64_t v)
{
  for (int i = 0; i < 8; ++i) {
    out.push_back(static_cast<unsigned char>(v >> (i * 8)));
  }
}

uint16_t readLe16(const unsigned char* p)
{
  return static_cast<uint16_t>(p[0]) |
         (static_cast<uint16_t>(p[1]) << 8);
}

uint32_t readLe32(const unsigned char* p)
{
  return static_cast<uint32_t>(p[0]) |
         (static_cast<uint32_t>(p[1]) << 8) |
         (static_cast<uint32_t>(p[2]) << 16) |
         (static_cast<uint32_t>(p[3]) << 24);
}

uint64_t readLe64(const unsigned char* p)
{
  uint64_t v = 0;
  for (int i = 0; i < 8; ++i) {
    v |= static_cast<uint64_t>(p[i]) << (i * 8);
  }
  return v;
}

// Append a string tag with 1-byte numeric name id.
// [TYPE_STRING|0x80][id][2-byte length LE][string bytes]
void appendTagString(std::vector<unsigned char>& payload, unsigned char tagId,
                     const std::string& value)
{
  payload.push_back(static_cast<unsigned char>(ed2ktag::TYPE_STRING | 0x80));
  payload.push_back(tagId);
  appendLe16(payload, static_cast<uint16_t>(value.size()));
  payload.insert(payload.end(), value.begin(), value.end());
}

// Append a uint32 tag with 1-byte numeric name id.
// [TYPE_UINT32|0x80][id][4-byte value LE]
void appendTagUint32(std::vector<unsigned char>& payload, unsigned char tagId,
                     uint32_t value)
{
  payload.push_back(static_cast<unsigned char>(ed2ktag::TYPE_UINT32 | 0x80));
  payload.push_back(tagId);
  appendLe32(payload, value);
}

// Process-wide ED2K user hash. eMule generates it once and persists it;
// bytes 5 and 14 follow the eMule convention (14 and 111).
const std::vector<unsigned char>& ed2kUserHash()
{
  static const std::vector<unsigned char> hash = [] {
    std::vector<unsigned char> h(16);
    std::random_device rd;
    for (auto& b : h) {
      b = static_cast<unsigned char>(rd());
    }
    h[5] = 14;
    h[14] = 111;
    return h;
  }();
  return hash;
}

void appendUserHash(std::vector<unsigned char>& payload)
{
  const auto& h = ed2kUserHash();
  payload.insert(payload.end(), h.begin(), h.end());
}

std::string ipFromWire(const unsigned char* p)
{
  // In FOUND_SOURCES / source-exchange entries the 4 address bytes are the
  // dotted-quad octets in order: b0.b1.b2.b3.
  char buf[16];
  snprintf(buf, sizeof(buf), "%u.%u.%u.%u", p[0], p[1], p[2], p[3]);
  return std::string(buf);
}

} // namespace

// ============================================================================
// Construction
// ============================================================================
Ed2kDownloadCommand::Ed2kDownloadCommand(
    cuid_t cuid, const std::shared_ptr<Request>& req,
    const std::shared_ptr<FileEntry>& fileEntry, RequestGroup* requestGroup,
    DownloadEngine* e, const std::shared_ptr<SocketCore>& s)
    : AbstractCommand(cuid, req, fileEntry, requestGroup, e, s),
      fileHash_(),
      fileSize_(0),
      downloadedLength_(0),
      state_(Ed2kState::SERVER_CONNECT),
      serverPort_(0),
      currentServerIndex_(0),
      serverRound_(0),
      currentSourceIndex_(0),
      serverSourceEnabled_(true),
      sourceExchangeEnabled_(true),
      kadEnabled_(false),
      sourceExchangeInterval_(300),
      listenPort_(4662),
      connectTimeout_(30),
      sourceExchangeSent_(false),
      maxSources_(100),
      currentKadNodeIndex_(0),
      kadBootstrapSent_(false),
      kadSearchSent_(false),
      kadState_(KadState::BOOTSTRAP),
      partSize_(Ed2kHelper::PART_SIZE),
      downloadOffset_(0),
      lastMarkedLength_(0),
      useI64Requests_(false),
      loginSent_(false),
      sourcesRequested_(false),
      helloSent_(false),
      emuleInfoSent_(false),
      fileInfoSent_(false),
      setReqFileIdSent_(false),
      fileStatusReceived_(false),
      uploadReqSent_(false),
      endOfDownloadSent_(false),
      connectionError_(false),
      verifyOffset_(0),
      verifyPartStart_(0),
      verifyStarted_(false)
{
  setTimeout(std::chrono::seconds(120));
  // The socket from Ed2kInitiateConnectionCommand may be mid non-blocking
  // connect; serverConnect() installs the proper event check itself.
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
    int port = opt->getAsInt(PREF_ED2K_LISTEN_PORT);
    if (port > 0 && port <= 65535) {
      listenPort_ = port;
    }
    int timeout = opt->getAsInt(PREF_ED2K_CONNECTION_TIMEOUT);
    if (timeout > 0) {
      connectTimeout_ = timeout;
    }
  }
  A2_LOG_INFO(fmt("CUID#%" PRId64 " - ED2K source discovery config:"
                  " server=%d sourceExchange=%d kad=%d interval=%ds"
                  " maxSources=%d listenPort=%d connectTimeout=%ds",
                  getCuid(), serverSourceEnabled_ ? 1 : 0,
                  sourceExchangeEnabled_ ? 1 : 0,
                  kadEnabled_ ? 1 : 0, sourceExchangeInterval_, maxSources_,
                  listenPort_, connectTimeout_));

  if (kadEnabled_) {
    initKad();
  }

  // Resume support: PieceStorage only ever had the *contiguous written
  // prefix* marked (see recordWrittenRange), so [0, completedLength) is
  // guaranteed to be on disk. Rebuild the in-memory range set from it.
  auto ps = getRequestGroup()->getPieceStorage();
  if (ps) {
    int64_t completed = ps->getCompletedLength();
    if (completed > 0) {
      writtenRanges_.push_back({0, completed});
      downloadedLength_ = completed;
      downloadOffset_ = completed;
      lastMarkedLength_ = completed;
      A2_LOG_INFO(fmt("CUID#%" PRId64 " - ED2K: resuming from offset %" PRId64,
                      getCuid(), completed));
    }
  }
}

Ed2kDownloadCommand::~Ed2kDownloadCommand()
{
  // Explicitly close the KAD UDP socket so it is released promptly rather
  // than waiting for shared_ptr destruction (which may be delayed while the
  // command object is still referenced by the engine's command queue).
  if (kadSocket_) {
    try {
      kadSocket_->closeConnection();
    }
    catch (...) {
    }
    kadSocket_.reset();
  }
}

bool Ed2kDownloadCommand::executeInternal()
{
  // Not used — execute() is overridden.
  return true;
}

void Ed2kDownloadCommand::setFileHash(const std::string& hash)
{
  fileHash_ = hash;
  // Pre-parse the hex hash once so hot-path callers (per-block message
  // construction / validation) can reuse rawFileHash_ without re-parsing.
  rawFileHash_ = Ed2kHelper::hexToHash(fileHash_);
}

void Ed2kDownloadCommand::setFileSize(uint64_t size)
{
  fileSize_ = size;
  useI64Requests_ = size > 0xFFFFFFFFULL;
  // Build the Part Availability Manager table now that file size is known.
  initParts();
}

void Ed2kDownloadCommand::setServerAddr(const std::string& addr, uint16_t port)
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
// ============================================================================
bool Ed2kDownloadCommand::execute()
{
  A2_LOG_DEBUG(fmt("CUID#%" PRId64 " - Ed2kDownloadCommand::execute()"
                   " state=%d offset=%" PRId64 "/%" PRId64,
                   getCuid(), static_cast<int>(state_),
                   downloadOffset_, static_cast<int64_t>(fileSize_)));

  // Update the ED2K context attribute so RPC getPeers can report sources.
  updateContextAttribute();

  if (getRequestGroup()->downloadFinished() ||
      getRequestGroup()->isHaltRequested()) {
    return true;
  }

  // Degenerate case: zero-length file — nothing to transfer.
  if (fileSize_ == 0 && state_ != Ed2kState::FINISHED) {
    A2_LOG_INFO(fmt("CUID#%" PRId64 " - ED2K: zero-length file, done",
                    getCuid()));
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
    // (SERVER_CONNECT, PEER_CONNECT, PEER_WAIT_CONNECT, VERIFY_HASH) the
    // socket is about to be replaced or already closed.
    if (state_ != Ed2kState::SERVER_CONNECT &&
        state_ != Ed2kState::PEER_CONNECT &&
        state_ != Ed2kState::PEER_WAIT_CONNECT &&
        state_ != Ed2kState::VERIFY_HASH) {
      if (!flushSendBuffer()) {
        if (connectionError_) {
          // Socket is dead — handle the error.
          connectionError_ = false;
          if (state_ == Ed2kState::SERVER_LOGIN ||
              state_ == Ed2kState::SERVER_GET_SOURCES ||
              state_ == Ed2kState::SERVER_WAIT_SOURCES) {
            A2_LOG_WARN(fmt("CUID#%" PRId64 " - ED2K: server socket dead,"
                            " trying next server", getCuid()));
            resetPeerState();
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
        // EAGAIN — wait for socket to become writable.
        setWriteCheckSocket(getSocket());
        addCommandSelf();
        return false;
      }
      disableWriteCheckSocket();
    }

    // State machine.
    while (true) {
      switch (state_) {
      case Ed2kState::SERVER_CONNECT:
        // If server-based source discovery is disabled, skip directly to
        // peer connection (sources must come from KAD or earlier exchange).
        if (!serverSourceEnabled_ && sources_.empty()) {
          if (sourceWaitStart_.difference() > std::chrono::seconds(60)) {
            sourceWaitStart_.reset();
            A2_LOG_WARN(fmt("CUID#%" PRId64
                            " - ED2K: no sources available, retrying",
                            getCuid()));
          }
          // KAD may still deliver sources; keep waiting.
          if (kadEnabled_ && kadSocket_) {
            kadStateMachine();
          }
          addCommandSelf();
          return false;
        }
        if (!serverSourceEnabled_) {
          state_ = Ed2kState::PEER_CONNECT;
          continue;
        }
        if (!serverConnect()) {
          addCommandSelf();
          return false;
        }
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
        continue;

      case Ed2kState::SERVER_WAIT_SOURCES:
        if (!serverWaitSources()) {
          addCommandSelf();
          return false;
        }
        continue;

      case Ed2kState::PEER_CONNECT:
        peerConnect();
        if (state_ == Ed2kState::PEER_WAIT_CONNECT) {
          setWriteCheckSocket(getSocket());
        }
        addCommandSelf();
        return false;

      case Ed2kState::PEER_WAIT_CONNECT:
        if (!peerWaitConnect()) {
          if (state_ == Ed2kState::PEER_WAIT_CONNECT) {
            setWriteCheckSocket(getSocket());
          }
          addCommandSelf();
          return false;
        }
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
        // Bind the file to this peer (filename + file id + part bitmap).
        state_ = Ed2kState::PEER_FILE_INFO;
        fileInfoSent_ = false;
        setReqFileIdSent_ = false;
        fileStatusReceived_ = false;
        continue;

      case Ed2kState::PEER_FILE_INFO:
        if (!peerFileInfo()) {
          if (state_ == Ed2kState::PEER_FILE_INFO) {
            setReadCheckSocket(getSocket());
          }
          addCommandSelf();
          return false;
        }
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
        continue;

      case Ed2kState::PEER_DOWNLOAD:
        if (!peerDownload()) {
          if (state_ == Ed2kState::PEER_DOWNLOAD) {
            setReadCheckSocket(getSocket());
          }
          addCommandSelf();
          return false;
        }
        // peerDownload() transitions to VERIFY_HASH when complete.
        continue;

      case Ed2kState::VERIFY_HASH:
        if (!verifyHash()) {
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
                                       size_t payloadLen,
                                       unsigned char protocol)
{
  // eDonkey packet framing: [4-byte length LE][protocol][opcode][payload]
  // length = bytes after the length field = 1(protocol) + 1(opcode) + payload
  uint32_t msgLen = static_cast<uint32_t>(payloadLen + 2);
  unsigned char header[6];
  header[0] = static_cast<unsigned char>(msgLen);
  header[1] = static_cast<unsigned char>(msgLen >> 8);
  header[2] = static_cast<unsigned char>(msgLen >> 16);
  header[3] = static_cast<unsigned char>(msgLen >> 24);
  header[4] = protocol;
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
    ssize_t written = 0;
    try {
      written = getSocket()->writeData(sendBuffer_.data() + totalWritten,
                                       sendBuffer_.size() - totalWritten);
    }
    catch (RecoverableException& e) {
      // Real error (not EAGAIN) — connection is dead.
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
      // EAGAIN — socket buffer full.
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
    unsigned char& msgType, std::vector<unsigned char>& payload,
    unsigned char& msgProtocol)
{
  // Loop: parse buffered frames first, read more from the socket when the
  // buffer holds no complete frame. Compressed (0xD4) frames are discarded
  // inside the loop so a following valid frame is parsed immediately.
  while (true) {
    if (recvBuffer_.size() >= ED2K_HEADER_LEN) {
      uint32_t msgLen = readLe32(recvBuffer_.data());

      if (msgLen > ED2K_MAX_MSG_SIZE || msgLen < 2) {
        // Stream desynchronization — the connection is unusable.
        throw DL_RETRY_EX(fmt("ED2K stream desync (frame length %u)",
                              msgLen));
      }

      size_t totalNeeded = ED2K_HEADER_LEN + msgLen;
      if (recvBuffer_.size() >= totalNeeded) {
        unsigned char protocolByte = recvBuffer_[ED2K_HEADER_LEN];
        if (protocolByte == ED2K_PROT_PACKED) {
          // Compressed frame: we never advertise compression support, so
          // these should not arrive; drop defensively.
          A2_LOG_WARN(fmt("CUID#%" PRId64 " - ED2K: dropping compressed"
                          " frame (%u bytes)", getCuid(), msgLen));
          recvBuffer_.erase(recvBuffer_.begin(),
                            recvBuffer_.begin() + totalNeeded);
          continue;
        }
        if (protocolByte != ED2K_PROT_EDONKEY &&
            protocolByte != ED2K_PROT_EMULE) {
          A2_LOG_WARN(fmt("CUID#%" PRId64 " - ED2K: unknown protocol byte"
                          " 0x%02x, dropping %u-byte frame",
                          getCuid(), protocolByte, msgLen));
          recvBuffer_.erase(recvBuffer_.begin(),
                            recvBuffer_.begin() + totalNeeded);
          continue;
        }

        msgProtocol = protocolByte;
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
    }

    // Guard against unbounded buffer growth on garbage input.
    if (recvBuffer_.size() > ED2K_MAX_MSG_SIZE) {
      throw DL_RETRY_EX("ED2K receive buffer overflow (desync)");
    }

    // Need more data — attempt one non-blocking read.
    unsigned char tmp[16384];
    size_t readLen = sizeof(tmp);
    getSocket()->readData(tmp, readLen);

    if (readLen > 0) {
      recvBuffer_.insert(recvBuffer_.end(), tmp, tmp + readLen);
      getCheckPoint().reset();
      continue;
    }
    if (!getSocket()->wantRead()) {
      // Connection closed (EOF).
      throw DL_RETRY_EX("ED2K connection closed by remote peer");
    }
    // EAGAIN — no complete message available.
    return false;
  }
}

// ============================================================================
// Server phase
// ============================================================================

bool Ed2kDownloadCommand::serverConnect()
{
  // Handles the full non-blocking connect lifecycle for ED2K servers:
  // 1. Initial call: socket from Ed2kInitiateConnectionCommand may have a
  //    pending non-blocking connect — check completion.
  // 2. Reconnection: create a new socket to the next server in the list.

  if (getSocket() && getSocket()->isOpen()) {
    if (!getSocket()->isWritable(0)) {
      // Connection still in progress — enforce the connect timeout.
      if (peerConnectTimer_.difference() >
          std::chrono::seconds(connectTimeout_)) {
        A2_LOG_WARN(fmt("CUID#%" PRId64 " - ED2K: server connect to %s:%u"
                        " timed out, trying next server",
                        getCuid(), serverAddr_.c_str(), serverPort_));
        resetPeerState();
        currentServerIndex_++;
      }
      else {
        setWriteCheckSocket(getSocket());
        return false;
      }
    }
    else {
      // Writable — check for connection errors via SO_ERROR.
      std::string err = getSocket()->getSocketError();
      if (err.empty()) {
        A2_LOG_INFO(fmt("CUID#%" PRId64 " - ED2K: server connection"
                        " established to %s:%u",
                        getCuid(), serverAddr_.c_str(), serverPort_));
        getCheckPoint().reset();
        loginSent_ = false;
        sourcesRequested_ = false;
        return true;
      }
      A2_LOG_WARN(fmt("CUID#%" PRId64 " - ED2K: server connection to"
                      " %s:%u failed: %s, trying next server",
                      getCuid(), serverAddr_.c_str(), serverPort_,
                      err.c_str()));
      resetPeerState();
      currentServerIndex_++;
    }
  }

  // Build the server list if empty.
  if (serverList_.empty()) {
    if (!serverAddr_.empty() && serverPort_ > 0) {
      serverList_.push_back({serverAddr_, serverPort_});
    }
    if (serverList_.empty()) {
      std::vector<Ed2kServerEntry> defaults;
      Ed2kHelper::getDefaultServers(defaults, getOption().get());
      for (const auto& s : defaults) {
        serverList_.push_back({s.addr, s.port});
      }
    }
  }

  // Pick the next server (with round limiting).
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

  resetPeerState();
  loginSent_ = false;
  sourcesRequested_ = false;

  try {
    createSocket();
    getSocket()->establishConnection(server.first, server.second);
    serverAddr_ = server.first;
    serverPort_ = server.second;
    peerConnectTimer_.reset();
  }
  catch (RecoverableException& e) {
    A2_LOG_WARN(fmt("CUID#%" PRId64 " - ED2K: failed to initiate connection"
                    " to server %s:%u: %s",
                    getCuid(), server.first.c_str(), server.second,
                    e.what()));
    currentServerIndex_++;
    return false;
  }

  // Non-blocking connect initiated — wait for the write event.
  setWriteCheckSocket(getSocket());
  return false;
}

bool Ed2kDownloadCommand::serverLogin()
{
  try {
    // Send OP_LOGINREQUEST (once).
    if (!loginSent_) {
      // Payload: [16B user hash][4B client id = 0][2B tcp port]
      //          [4B tag count][tags...]
      std::vector<unsigned char> payload;
      appendUserHash(payload);
      appendLe32(payload, 0); // client id = 0 (new login)
      appendLe16(payload, static_cast<uint16_t>(listenPort_));
      appendLe32(payload, 4); // tag count

      appendTagString(payload, ed2ktag::CT_NAME, "LinkCore");
      appendTagUint32(payload, ed2ktag::CT_VERSION, 0x3C); // eMule 0.60
      appendTagUint32(payload, ed2ktag::CT_PORT,
                      static_cast<uint32_t>(listenPort_));
      appendTagUint32(payload, ed2ktag::CT_SERVER_FLAGS, 0x01);

      queueMessage(ed2kop::LOGIN_REQUEST, payload.data(), payload.size());
      loginSent_ = true;

      A2_LOG_INFO(fmt("CUID#%" PRId64 " - ED2K sending login request to %s:%u",
                      getCuid(), serverAddr_.c_str(), serverPort_));

      if (!flushSendBuffer()) {
        if (connectionError_) {
          return false;
        }
        setWriteCheckSocket(getSocket());
        return false;
      }
    }

    // Receive messages until OP_IDCHANGE.
    unsigned char msgType = 0, msgProtocol = 0;
    std::vector<unsigned char> payload;
    while (true) {
      if (!tryReceiveMessage(msgType, payload, msgProtocol)) {
        return false;
      }

      // Server chatter — log and skip.
      if (msgProtocol == ED2K_PROT_EDONKEY &&
          (msgType == ed2kop::SERVER_MESSAGE ||
           msgType == ed2kop::SERVER_IDENT)) {
        continue;
      }

      if (msgProtocol == ED2K_PROT_EDONKEY && msgType == ed2kop::ID_CHANGE) {
        break;
      }

      A2_LOG_WARN(fmt("CUID#%" PRId64 " - ED2K login: unexpected msg 0x%02x"
                      " (proto 0x%02x), trying next server",
                      getCuid(), msgType, msgProtocol));
      resetPeerState();
      currentServerIndex_++;
      state_ = Ed2kState::SERVER_CONNECT;
      return false;
    }

    // Parse ID_CHANGE: [4B user id][4B tcp flags][4B aux port][4B client ip]
    if (payload.size() >= 4) {
      uint32_t userId = readLe32(payload.data());
      bool highId = userId >= 0x01000000;
      A2_LOG_INFO(fmt("CUID#%" PRId64 " - ED2K login accepted, user_id=%u"
                      " (%s)", getCuid(), userId,
                      highId ? "HighID" : "LowID"));
    }

    return true;
  }
  catch (DlAbortEx&) {
    throw;
  }
  catch (RecoverableException& e) {
    A2_LOG_WARN(fmt("CUID#%" PRId64 " - ED2K server login error: %s,"
                    " trying next server", getCuid(), e.what()));
    resetPeerState();
    currentServerIndex_++;
    state_ = Ed2kState::SERVER_CONNECT;
    return false;
  }
}

bool Ed2kDownloadCommand::serverGetSources()
{
  try {
    // Send OP_GETSOURCES (once per server session).
    if (!sourcesRequested_) {
      std::vector<unsigned char> rawHash = rawFileHash_;
      if (rawHash.size() != 16) {
        throw DL_ABORT_EX2("Invalid ED2K file hash for source request",
                           error_code::UNKNOWN_ERROR);
      }

      queueMessage(ed2kop::GET_SOURCES, rawHash.data(), 16);
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

    // Receive until OP_FOUNDSOURCES.
    unsigned char msgType = 0, msgProtocol = 0;
    std::vector<unsigned char> payload;
    while (true) {
      if (!tryReceiveMessage(msgType, payload, msgProtocol)) {
        return false;
      }

      if (msgProtocol == ED2K_PROT_EDONKEY &&
          (msgType == ed2kop::SERVER_MESSAGE ||
           msgType == ed2kop::SERVER_IDENT)) {
        continue;
      }

      if (msgProtocol == ED2K_PROT_EDONKEY &&
          msgType == ed2kop::FOUND_SOURCES) {
        break;
      }

      A2_LOG_INFO(fmt("CUID#%" PRId64 " - ED2K: unexpected msg 0x%02x while"
                      " waiting for sources; entering wait state",
                      getCuid(), msgType));
      state_ = Ed2kState::SERVER_WAIT_SOURCES;
      sourceWaitStart_.reset();
      return true;
    }

    // Parse FOUND_SOURCES: [16B hash][1B count][count x (4B ip + 2B port)]
    if (payload.size() < 17) {
      A2_LOG_INFO(fmt("CUID#%" PRId64 " - ED2K: no sources in response",
                      getCuid()));
      state_ = Ed2kState::SERVER_WAIT_SOURCES;
      sourceWaitStart_.reset();
      return true;
    }

    // Sanity: the response must be about our file.
    std::vector<unsigned char> rawHash = rawFileHash_;
    if (rawHash.size() == 16 &&
        memcmp(payload.data(), rawHash.data(), 16) != 0) {
      A2_LOG_WARN(fmt("CUID#%" PRId64 " - ED2K: FOUND_SOURCES hash mismatch,"
                      " ignoring", getCuid()));
      return false;
    }

    uint8_t sourceCount = payload[16];
    size_t available = (payload.size() - 17) / 6;
    if (sourceCount > available) {
      sourceCount = static_cast<uint8_t>(available);
    }
    A2_LOG_INFO(fmt("CUID#%" PRId64 " - ED2K found %u sources",
                    getCuid(), sourceCount));

    size_t added = 0;
    for (size_t i = 0; i < sourceCount; ++i) {
      const unsigned char* entry = payload.data() + 17 + i * 6;
      uint32_t id = readLe32(entry);
      uint16_t port = readLe16(entry + 4);

      // Skip LowID sources (cannot connect directly).
      if (id < 0x01000000 || port == 0) {
        continue;
      }

      if (addSource(ipFromWire(entry), port)) {
        ++added;
      }
    }
    A2_LOG_INFO(fmt("CUID#%" PRId64 " - ED2K: %zu new sources added"
                    " (total %zu)", getCuid(), added, sources_.size()));

    if (sources_.empty()) {
      state_ = Ed2kState::SERVER_WAIT_SOURCES;
      sourceWaitStart_.reset();
      return true;
    }

    // Server no longer needed — the peer phase uses its own socket.
    disableReadCheckSocket();
    disableWriteCheckSocket();
    try {
      if (getSocket() && getSocket()->isOpen()) {
        getSocket()->closeConnection();
      }
    }
    catch (...) {
    }

    currentSourceIndex_ = 0;
    state_ = Ed2kState::PEER_CONNECT;
    return true;
  }
  catch (DlAbortEx&) {
    throw;
  }
  catch (RecoverableException& e) {
    A2_LOG_WARN(fmt("CUID#%" PRId64 " - ED2K server get sources error: %s,"
                    " trying next server", getCuid(), e.what()));
    resetPeerState();
    currentServerIndex_++;
    state_ = Ed2kState::SERVER_CONNECT;
    return false;
  }
}

bool Ed2kDownloadCommand::serverWaitSources()
{
  auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
      sourceWaitStart_.difference()).count();

  if (elapsed < SOURCE_WAIT_SECONDS) {
    return false;
  }

  A2_LOG_INFO(fmt("CUID#%" PRId64 " - ED2K: retrying source request",
                  getCuid()));
  return reconnectServer();
}

// ============================================================================
// Peer phase
// ============================================================================

void Ed2kDownloadCommand::resetPeerState()
{
  // Close the current socket and clear ALL protocol state. Critical when
  // switching between sockets (server<->peer, peer<->peer): stale buffered
  // data would corrupt the fresh stream.
  disableReadCheckSocket();
  disableWriteCheckSocket();
  try {
    if (getSocket() && getSocket()->isOpen()) {
      getSocket()->closeConnection();
    }
  }
  catch (...) {
  }

  sendBuffer_.clear();
  recvBuffer_.clear();
  inflightBlocks_.clear();

  helloSent_ = false;
  emuleInfoSent_ = false;
  fileInfoSent_ = false;
  setReqFileIdSent_ = false;
  fileStatusReceived_ = false;
  uploadReqSent_ = false;
  endOfDownloadSent_ = false;
  sourceExchangeSent_ = false;
  connectionError_ = false;

  getCheckPoint().reset();
}

void Ed2kDownloadCommand::tryNextPeer()
{
  // Mark the current peer as failed (cooldown prevents immediate retry).
  // Only peers we actually engaged with are marked; EXPIRED entries and
  // untouched NEW entries are left alone.
  if (currentSourceIndex_ < sources_.size()) {
    const auto& cur = sources_[currentSourceIndex_];
    if (cur.state == SourceState::CONNECTING ||
        cur.state == SourceState::CONNECTED ||
        cur.state == SourceState::DOWNLOADING ||
        cur.state == SourceState::QUEUED) {
      markPeerFailed(cur.addr, cur.port);
    }
  }

  resetPeerState();

  // Advance past FAILED/EXPIRED sources. Failed entries stay in the pool so
  // the cooldown logic can prevent immediate retries.
  currentSourceIndex_++;
  while (currentSourceIndex_ < sources_.size()) {
    const auto& s = sources_[currentSourceIndex_];
    if (s.state == SourceState::EXPIRED) {
      currentSourceIndex_++;
      continue;
    }
    if (s.state == SourceState::FAILED &&
        isPeerInCooldown(s.addr, s.port)) {
      currentSourceIndex_++;
      continue;
    }
    break;
  }

  if (currentSourceIndex_ >= sources_.size()) {
    A2_LOG_INFO(fmt("CUID#%" PRId64 " - ED2K: exhausted all %zu peer sources,"
                    " reconnecting to server for fresh sources",
                    getCuid(), sources_.size()));
    currentSourceIndex_ = 0;

    if (!reconnectServer()) {
      state_ = Ed2kState::FAILURE;
    }
    return;
  }

  A2_LOG_INFO(fmt("CUID#%" PRId64 " - ED2K trying next peer source %zu/%zu",
                  getCuid(), currentSourceIndex_ + 1, sources_.size()));
  state_ = Ed2kState::PEER_CONNECT;
}

bool Ed2kDownloadCommand::reconnectServer()
{
  resetPeerState();
  loginSent_ = false;
  sourcesRequested_ = false;

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

  state_ = Ed2kState::SERVER_CONNECT;
  return true;
}

bool Ed2kDownloadCommand::peerConnect()
{
  if (currentSourceIndex_ >= sources_.size()) {
    tryNextPeer();
    return false;
  }

  PeerSource& src = sources_[currentSourceIndex_];

  // Skip sources that are unusable right now. Note: returning false here
  // re-enters peerConnect() on the next engine tick — execute() re-queues
  // this command, so we must NOT call addCommandSelf() ourselves.
  if (src.state == SourceState::EXPIRED ||
      (src.state == SourceState::FAILED &&
       isPeerInCooldown(src.addr, src.port))) {
    currentSourceIndex_++;
    return false;
  }

  src.state = SourceState::CONNECTING;
  src.lastActive.reset();

  A2_LOG_INFO(fmt("CUID#%" PRId64 " - ED2K connecting to peer %s:%u",
                  getCuid(), src.addr.c_str(), src.port));

  resetPeerState();
  createSocket();

  try {
    getSocket()->establishConnection(src.addr, src.port);
  }
  catch (RecoverableException& e) {
    A2_LOG_WARN(fmt("CUID#%" PRId64 " - ED2K failed to connect to peer"
                    " %s:%u: %s",
                    getCuid(), src.addr.c_str(), src.port, e.what()));
    tryNextPeer();
    return false;
  }

  peerConnectTimer_.reset();
  state_ = Ed2kState::PEER_WAIT_CONNECT;
  return false;
}

bool Ed2kDownloadCommand::peerWaitConnect()
{
  if (!getSocket()->isWritable(0)) {
    // Still connecting — enforce the connect timeout.
    if (peerConnectTimer_.difference() >
        std::chrono::seconds(connectTimeout_)) {
      A2_LOG_WARN(fmt("CUID#%" PRId64 " - ED2K peer connect to %s:%u"
                      " timed out",
                      getCuid(),
                      currentSourceIndex_ < sources_.size()
                          ? sources_[currentSourceIndex_].addr.c_str()
                          : "?",
                      currentSourceIndex_ < sources_.size()
                          ? sources_[currentSourceIndex_].port
                          : 0));
      tryNextPeer();
    }
    return false;
  }

  std::string err = getSocket()->getSocketError();
  if (!err.empty()) {
    A2_LOG_WARN(fmt("CUID#%" PRId64 " - ED2K peer connection failed: %s",
                    getCuid(), err.c_str()));
    tryNextPeer();
    return false;
  }

  A2_LOG_INFO(fmt("CUID#%" PRId64 " - ED2K peer connection established"
                  " (%s:%u)",
                  getCuid(),
                  sources_[currentSourceIndex_].addr.c_str(),
                  sources_[currentSourceIndex_].port));

  getCheckPoint().reset();
  return true;
}

bool Ed2kDownloadCommand::peerHandshake()
{
  try {
    // Send OP_HELLO + OP_EMULEINFO (once).
    if (!helloSent_) {
      // OP_HELLO payload:
      //   [1B hash size = 16][16B user hash][4B client id = 0]
      //   [2B tcp port][4B tag count][tags...]
      //   [4B server ip][2B server port]   (post-tag data)
      std::vector<unsigned char> payload;
      payload.push_back(16);
      appendUserHash(payload);
      appendLe32(payload, 0);
      appendLe16(payload, static_cast<uint16_t>(listenPort_));
      appendLe32(payload, 2); // tag count
      appendTagString(payload, ed2ktag::CT_NAME, "LinkCore");
      appendTagUint32(payload, ed2ktag::CT_VERSION, 0x3C);

      // Trailing server address (as in eMule's hello packet).
      if (!serverAddr_.empty()) {
        struct in_addr inAddr;
        if (inet_pton(AF_INET, serverAddr_.c_str(), &inAddr) == 1) {
          const unsigned char* ipBytes =
              reinterpret_cast<const unsigned char*>(&inAddr.s_addr);
          payload.insert(payload.end(), ipBytes, ipBytes + 4);
        }
        else {
          appendLe32(payload, 0);
        }
      }
      else {
        appendLe32(payload, 0);
      }
      appendLe16(payload, serverPort_);

      queueMessage(ed2kop::HELLO, payload.data(), payload.size());
      helloSent_ = true;
    }

    // OP_EMULEINFO (0xC5): advertise eMule compatibility so the peer
    // enables source exchange and large-file transfers. Compression is
    // explicitly advertised as 0 — we cannot parse compressed frames.
    if (!emuleInfoSent_) {
      std::vector<unsigned char> payload;
      payload.push_back(0x01); // extended protocol version (EMULE_PROTOCOL)
      payload.push_back(0x3C); // client version (eMule 0.60)
      appendLe32(payload, 4);  // tag count
      appendTagUint32(payload, ed2ktag::ET_COMPRESSION, 0);
      appendTagUint32(payload, ed2ktag::ET_SOURCEEXCHANGE, 4);
      appendTagUint32(payload, ed2ktag::ET_EXTENDEDREQUEST, 2);
      appendTagUint32(payload, ed2ktag::ET_FEATURES, 0x06);

      queueMessage(ed2kop::EMULE_INFO, payload.data(), payload.size(),
                   ED2K_PROT_EMULE);
      emuleInfoSent_ = true;

      A2_LOG_DEBUG(fmt("CUID#%" PRId64 " - ED2K sending peer hello",
                       getCuid()));

      if (!flushSendBuffer()) {
        if (connectionError_) {
          return false;
        }
        setWriteCheckSocket(getSocket());
        return false;
      }
    }

    // Receive until OP_HELLOANSWER.
    unsigned char msgType = 0, msgProtocol = 0;
    std::vector<unsigned char> payload;
    while (true) {
      if (!tryReceiveMessage(msgType, payload, msgProtocol)) {
        return false;
      }

      if (msgProtocol == ED2K_PROT_EMULE) {
        // eMule chatter before hello answer — answer EMULEINFO, skip rest.
        if (msgType == ed2kop::EMULE_INFO) {
          std::vector<unsigned char> answer;
          answer.push_back(0x01);
          answer.push_back(0x3C);
          appendLe32(answer, 4);
          appendTagUint32(answer, ed2ktag::ET_COMPRESSION, 0);
          appendTagUint32(answer, ed2ktag::ET_SOURCEEXCHANGE, 4);
          appendTagUint32(answer, ed2ktag::ET_EXTENDEDREQUEST, 2);
          appendTagUint32(answer, ed2ktag::ET_FEATURES, 0x06);
          queueMessage(ed2kop::EMULE_INFO_ANSWER, answer.data(),
                       answer.size(), ED2K_PROT_EMULE);
          if (!flushSendBuffer() && connectionError_) {
            return false;
          }
        }
        continue;
      }

      if (msgType == ed2kop::QUEUE_RANK) {
        // Peer may already report queue position — remember it.
        if (currentSourceIndex_ < sources_.size() && payload.size() >= 4) {
          sources_[currentSourceIndex_].queuePosition =
              static_cast<int>(readLe32(payload.data()));
        }
        continue;
      }

      if (msgType != ed2kop::HELLO_ANSWER) {
        A2_LOG_WARN(fmt("CUID#%" PRId64 " - ED2K peer handshake: unexpected"
                        " message 0x%02x, trying next peer",
                        getCuid(), msgType));
        tryNextPeer();
        return false;
      }

      break;
    }

    if (currentSourceIndex_ < sources_.size()) {
      sources_[currentSourceIndex_].state = SourceState::CONNECTED;
      sources_[currentSourceIndex_].lastActive.reset();
    }
    A2_LOG_INFO(fmt("CUID#%" PRId64 " - ED2K peer handshake completed",
                    getCuid()));
    return true;
  }
  catch (DlAbortEx&) {
    throw;
  }
  catch (RecoverableException& e) {
    A2_LOG_WARN(fmt("CUID#%" PRId64 " - ED2K peer handshake error: %s,"
                    " trying next peer", getCuid(), e.what()));
    tryNextPeer();
    return false;
  }
}

bool Ed2kDownloadCommand::peerFileInfo()
{
  // Bind the file to this peer: OP_REQUESTFILENAME -> OP_REQFILENAMEANSWER,
  // then OP_SETREQFILEID -> optional OP_FILESTATUS (part availability
  // bitmap, only sent by peers that hold the file partially).
  try {
    std::vector<unsigned char> rawHash = rawFileHash_;
    if (rawHash.size() != 16) {
      throw DL_ABORT_EX2("Invalid ED2K file hash",
                         error_code::UNKNOWN_ERROR);
    }

    if (!fileInfoSent_) {
      queueMessage(ed2kop::REQUEST_FILENAME, rawHash.data(), 16);
      fileInfoSent_ = true;
      fileInfoTimer_.reset();
      if (!flushSendBuffer()) {
        if (connectionError_) {
          return false;
        }
        setWriteCheckSocket(getSocket());
        return false;
      }
    }

    unsigned char msgType = 0, msgProtocol = 0;
    std::vector<unsigned char> payload;
    while (true) {
      if (!tryReceiveMessage(msgType, payload, msgProtocol)) {
        if (!setReqFileIdSent_) {
          // Waiting for the filename answer — give up on a dead peer.
          if (fileInfoTimer_.difference() > std::chrono::seconds(15)) {
            A2_LOG_WARN(fmt("CUID#%" PRId64 " - ED2K: filename answer"
                            " timeout, trying next peer", getCuid()));
            tryNextPeer();
          }
        }
        else if (!fileStatusReceived_) {
          // FILESTATUS is optional (complete files have no bitmap).
          // Proceed optimistically after a short grace period.
          if (fileInfoTimer_.difference() > std::chrono::seconds(3)) {
            fileStatusReceived_ = true;
            return true;
          }
        }
        return false;
      }

      if (msgProtocol == ED2K_PROT_EMULE) {
        if (msgType == ed2kop::ANSWER_SOURCES ||
            msgType == ed2kop::ANSWER_SOURCES2) {
          parseSourcesAnswer(payload);
        }
        continue;
      }

      if (msgType == ed2kop::FILE_REQ_ANS_NO_FIL) {
        A2_LOG_INFO(fmt("CUID#%" PRId64 " - ED2K: peer does not have the"
                        " file, trying next peer", getCuid()));
        if (currentSourceIndex_ < sources_.size()) {
          markPeerFailed(sources_[currentSourceIndex_].addr,
                         sources_[currentSourceIndex_].port,
                         true /* permanent */);
        }
        tryNextPeer();
        return false;
      }

      if (msgType == ed2kop::QUEUE_RANK) {
        if (currentSourceIndex_ < sources_.size() && payload.size() >= 4) {
          sources_[currentSourceIndex_].queuePosition =
              static_cast<int>(readLe32(payload.data()));
        }
        continue;
      }

      if (!setReqFileIdSent_) {
        if (msgType != ed2kop::REQ_FILENAME_ANSWER) {
          A2_LOG_DEBUG(fmt("CUID#%" PRId64 " - ED2K: skipping msg 0x%02x"
                           " during file info", getCuid(), msgType));
          continue;
        }
        // [16B hash][4B name length][name] — log the remote name.
        if (payload.size() >= 20) {
          uint32_t nameLen = readLe32(payload.data() + 16);
          if (nameLen > 0 && 20 + nameLen <= payload.size() && nameLen < 512) {
            std::string remoteName(
                reinterpret_cast<const char*>(payload.data() + 20), nameLen);
            A2_LOG_INFO(fmt("CUID#%" PRId64 " - ED2K peer file name: %s",
                            getCuid(), remoteName.c_str()));
          }
        }
        queueMessage(ed2kop::SET_REQ_FILE_ID, rawHash.data(), 16);
        setReqFileIdSent_ = true;
        fileInfoTimer_.reset();
        if (!flushSendBuffer()) {
          if (connectionError_) {
            return false;
          }
          setWriteCheckSocket(getSocket());
          return false;
        }
        continue;
      }

      // Awaiting optional FILESTATUS.
      if (msgType == ed2kop::FILE_STATUS) {
        // [16B hash][2B part count][ceil(count/8) bytes bitmap, LSB first]
        if (payload.size() >= 18 && currentSourceIndex_ < sources_.size()) {
          uint16_t partCount = readLe16(payload.data() + 16);
          size_t bitmapBytes = (partCount + 7) / 8;
          if (18 + bitmapBytes <= payload.size()) {
            std::vector<bool> bitmap(partCount, false);
            for (uint16_t i = 0; i < partCount; ++i) {
              bitmap[i] =
                  (payload[18 + i / 8] & (1 << (i % 8))) != 0;
            }
            updatePartAvailability(currentSourceIndex_, bitmap);
            size_t have = 0;
            for (bool b : bitmap) {
              if (b) {
                ++have;
              }
            }
            A2_LOG_INFO(fmt("CUID#%" PRId64 " - ED2K peer has %zu/%u parts",
                            getCuid(), have, partCount));
          }
        }
        fileStatusReceived_ = true;
        return true;
      }

      // Any other message: the peer is done with file info — proceed.
      A2_LOG_DEBUG(fmt("CUID#%" PRId64 " - ED2K: msg 0x%02x ends file info"
                       " phase", getCuid(), msgType));
      fileStatusReceived_ = true;
      return true;
    }
  }
  catch (DlAbortEx&) {
    throw;
  }
  catch (RecoverableException& e) {
    A2_LOG_WARN(fmt("CUID#%" PRId64 " - ED2K file info error: %s,"
                    " trying next peer", getCuid(), e.what()));
    tryNextPeer();
    return false;
  }
}

bool Ed2kDownloadCommand::peerSourceExchange()
{
  // Ask the connected peer for additional sources (best-effort).
  try {
    if (!sourceExchangeSent_) {
      sendSourceExchangeRequest();
      if (!flushSendBuffer()) {
        if (connectionError_) {
          return false;
        }
        setWriteCheckSocket(getSocket());
        return false;
      }
    }

    unsigned char msgType = 0, msgProtocol = 0;
    std::vector<unsigned char> payload;
    if (!tryReceiveMessage(msgType, payload, msgProtocol)) {
      // Wait at most 5 seconds for an answer, then proceed.
      if (sourceExchangeTimer_.difference() > std::chrono::seconds(5)) {
        A2_LOG_INFO(fmt("CUID#%" PRId64
                        " - ED2K: source exchange timed out, proceeding",
                        getCuid()));
        return true;
      }
      return false;
    }

    if (msgProtocol == ED2K_PROT_EMULE &&
        (msgType == ed2kop::ANSWER_SOURCES ||
         msgType == ed2kop::ANSWER_SOURCES2)) {
      parseSourcesAnswer(payload);
    }
    else if (msgProtocol == ED2K_PROT_EDONKEY &&
             msgType == ed2kop::FILE_REQ_ANS_NO_FIL) {
      if (currentSourceIndex_ < sources_.size()) {
        markPeerFailed(sources_[currentSourceIndex_].addr,
                       sources_[currentSourceIndex_].port, true);
      }
      tryNextPeer();
      return false;
    }
    // Other messages are handled again in the next phase.

    return true;
  }
  catch (DlAbortEx&) {
    throw;
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
    if (!uploadReqSent_) {
      std::vector<unsigned char> rawHash = rawFileHash_;
      if (rawHash.size() != 16) {
        throw DL_ABORT_EX2("Invalid ED2K file hash for upload request",
                           error_code::UNKNOWN_ERROR);
      }

      queueMessage(ed2kop::START_UPLOAD_REQ, rawHash.data(), 16);
      uploadReqSent_ = true;
      queueWaitTimer_.reset();

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

    unsigned char msgType = 0, msgProtocol = 0;
    std::vector<unsigned char> payload;
    while (true) {
      if (!tryReceiveMessage(msgType, payload, msgProtocol)) {
        // No data right now. If we're queued on the peer's upload queue,
        // waiting is normal — but not forever.
        if (currentSourceIndex_ < sources_.size() &&
            sources_[currentSourceIndex_].state == SourceState::QUEUED) {
          // Keep the inactivity timer satisfied while queued (the peer
          // holds the connection open but sends nothing).
          getCheckPoint().reset();
          if (queueWaitTimer_.difference() >
              std::chrono::seconds(QUEUE_WAIT_SECONDS)) {
            A2_LOG_INFO(fmt("CUID#%" PRId64 " - ED2K: queue wait exceeded"
                            " %ds, trying next peer",
                            getCuid(), QUEUE_WAIT_SECONDS));
            tryNextPeer();
          }
        }
        else if (queueWaitTimer_.difference() >
                 std::chrono::seconds(PEER_STALL_SECONDS)) {
          // Upload request sent but the peer never answered.
          A2_LOG_INFO(fmt("CUID#%" PRId64 " - ED2K: no answer to upload"
                          " request, trying next peer", getCuid()));
          tryNextPeer();
        }
        return false;
      }

      if (msgProtocol == ED2K_PROT_EMULE) {
        if (msgType == ed2kop::ANSWER_SOURCES ||
            msgType == ed2kop::ANSWER_SOURCES2) {
          parseSourcesAnswer(payload);
        }
        else if (msgType == ed2kop::QUEUE_RANKING) {
          int rank = -1;
          if (payload.size() >= 2) {
            rank = readLe16(payload.data());
          }
          if (currentSourceIndex_ < sources_.size()) {
            sources_[currentSourceIndex_].state = SourceState::QUEUED;
            sources_[currentSourceIndex_].queuePosition = rank;
          }
          getCheckPoint().reset();
        }
        continue;
      }

      if (msgType == ed2kop::ACCEPT_UPLOAD_REQ) {
        A2_LOG_INFO(fmt("CUID#%" PRId64 " - ED2K upload slot accepted",
                        getCuid()));
        if (currentSourceIndex_ < sources_.size()) {
          sources_[currentSourceIndex_].state = SourceState::DOWNLOADING;
          sources_[currentSourceIndex_].queuePosition = -1;
          sources_[currentSourceIndex_].lastActive.reset();
        }
        return true;
      }

      if (msgType == ed2kop::QUEUE_RANK) {
        int rank = -1;
        if (payload.size() >= 4) {
          rank = static_cast<int>(readLe32(payload.data()));
        }
        if (currentSourceIndex_ < sources_.size()) {
          sources_[currentSourceIndex_].state = SourceState::QUEUED;
          sources_[currentSourceIndex_].queuePosition = rank;
        }
        A2_LOG_INFO(fmt("CUID#%" PRId64 " - ED2K queued for upload slot"
                        " (rank=%d)", getCuid(), rank));
        getCheckPoint().reset();
        continue;
      }

      if (msgType == ed2kop::FILE_REQ_ANS_NO_FIL) {
        if (currentSourceIndex_ < sources_.size()) {
          markPeerFailed(sources_[currentSourceIndex_].addr,
                         sources_[currentSourceIndex_].port, true);
        }
        tryNextPeer();
        return false;
      }

      if (msgType == ed2kop::CANCEL_TRANSFER) {
        A2_LOG_INFO(fmt("CUID#%" PRId64 " - ED2K peer cancelled transfer,"
                        " trying next peer", getCuid()));
        tryNextPeer();
        return false;
      }

      A2_LOG_DEBUG(fmt("CUID#%" PRId64 " - ED2K skipping message 0x%02x"
                       " during upload request", getCuid(), msgType));
    }
  }
  catch (DlAbortEx&) {
    throw;
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
    // --- Periodic source discovery during download (non-blocking) ---

    // 1. Dynamic-interval source exchange with the current peer.
    if (sourceExchangeEnabled_ &&
        sourceExchangeTimer_.difference() >
            std::chrono::seconds(getDynamicExchangeInterval())) {
      sendSourceExchangeRequest();
      // Best-effort flush; a failure here is handled on the next tick.
      flushSendBuffer();
    }

    // 2. KAD source lookup state machine.
    if (kadEnabled_ && kadSocket_) {
      kadStateMachine();
    }

    // 3. Periodic server source refresh when sources are scarce.
    checkServerSourceRefresh();
    if (state_ != Ed2kState::PEER_DOWNLOAD) {
      // Server refresh re-routed us back to the server phase. execute()
      // re-queues this command — do NOT call addCommandSelf() here.
      return false;
    }

    // --- Main request/receive loop ---
    while (true) {
      // Completion check: the whole contiguous prefix is on disk.
      if (downloadComplete()) {
        A2_LOG_INFO(fmt("CUID#%" PRId64 " - ED2K: all data received"
                        " (%" PRId64 " bytes), verifying hash",
                        getCuid(), downloadedLength_));
        // Politely notify the peer, then drop the connection.
        if (!endOfDownloadSent_) {
          std::vector<unsigned char> rawHash =
              rawFileHash_;
          if (rawHash.size() == 16) {
            queueMessage(ed2kop::END_OF_DOWNLOAD, rawHash.data(), 16);
            endOfDownloadSent_ = true;
          }
        }
        flushSendBuffer(); // best effort
        disableReadCheckSocket();
        disableWriteCheckSocket();
        try {
          if (getSocket() && getSocket()->isOpen()) {
            getSocket()->closeConnection();
          }
        }
        catch (...) {
        }
        inflightBlocks_.clear();
        state_ = Ed2kState::VERIFY_HASH;
        verifyStarted_ = false;
        return true;
      }

      // Keep the pipeline full.
      if (!fillBlockPipeline()) {
        if (connectionError_) {
          connectionError_ = false;
          tryNextPeer();
          return false;
        }
        // EAGAIN — wait for writability.
        setWriteCheckSocket(getSocket());
        return false;
      }

      // If the pipeline is empty after filling, this peer cannot provide
      // anything we still need.
      if (inflightBlocks_.empty()) {
        A2_LOG_INFO(fmt("CUID#%" PRId64 " - ED2K: peer has no more needed"
                        " parts, trying next peer", getCuid()));
        tryNextPeer();
        return false;
      }

      // Receive one message.
      unsigned char msgType = 0, msgProtocol = 0;
      std::vector<unsigned char> payload;
      if (!tryReceiveMessage(msgType, payload, msgProtocol)) {
        // No data — stall detection: if the peer stopped delivering
        // blocks, switch to another source.
        if (currentSourceIndex_ < sources_.size()) {
          const auto& src = sources_[currentSourceIndex_];
          if (src.lastActive.difference() >
              std::chrono::seconds(PEER_STALL_SECONDS)) {
            A2_LOG_INFO(fmt("CUID#%" PRId64 " - ED2K: peer stalled for"
                            " %ds, trying next peer",
                            getCuid(), PEER_STALL_SECONDS));
            tryNextPeer();
          }
        }
        return false;
      }

      if (msgProtocol == ED2K_PROT_EMULE) {
        if (msgType == ed2kop::ANSWER_SOURCES ||
            msgType == ed2kop::ANSWER_SOURCES2) {
          parseSourcesAnswer(payload);
        }
        else if (msgType == ed2kop::QUEUE_RANKING) {
          if (currentSourceIndex_ < sources_.size() &&
              payload.size() >= 2) {
            sources_[currentSourceIndex_].queuePosition =
                readLe16(payload.data());
          }
        }
        continue;
      }

      if (msgType == ed2kop::SENDING_PART) {
        if (!handleSendingPart(payload, false)) {
          return false;
        }
        continue;
      }

      if (msgType == ed2kop::SENDING_PART_I64) {
        if (!handleSendingPart(payload, true)) {
          return false;
        }
        continue;
      }

      if (msgType == ed2kop::QUEUE_RANK) {
        if (currentSourceIndex_ < sources_.size() && payload.size() >= 4) {
          sources_[currentSourceIndex_].queuePosition =
              static_cast<int>(readLe32(payload.data()));
        }
        continue;
      }

      if (msgType == ed2kop::FILE_REQ_ANS_NO_FIL) {
        if (currentSourceIndex_ < sources_.size()) {
          markPeerFailed(sources_[currentSourceIndex_].addr,
                         sources_[currentSourceIndex_].port, true);
        }
        tryNextPeer();
        return false;
      }

      if (msgType == ed2kop::CANCEL_TRANSFER) {
        A2_LOG_INFO(fmt("CUID#%" PRId64 " - ED2K peer cancelled transfer,"
                        " trying next peer", getCuid()));
        tryNextPeer();
        return false;
      }

      A2_LOG_DEBUG(fmt("CUID#%" PRId64 " - ED2K skipping message 0x%02x"
                       " during download", getCuid(), msgType));
    }
  }
  catch (DlAbortEx&) {
    throw;
  }
  catch (RecoverableException& e) {
    A2_LOG_WARN(fmt("CUID#%" PRId64 " - ED2K download error: %s,"
                    " trying next peer", getCuid(), e.what()));
    tryNextPeer();
    return false;
  }
}

// ============================================================================
// Block scheduling / disk I/O
// ============================================================================

bool Ed2kDownloadCommand::fillBlockPipeline()
{
  while (inflightBlocks_.size() < MAX_INFLIGHT_BLOCKS) {
    // Gather up to BLOCKS_PER_MESSAGE blocks for one OP_REQUESTPARTS.
    std::vector<BlockRequest> batch;
    while (batch.size() < BLOCKS_PER_MESSAGE &&
           inflightBlocks_.size() + batch.size() < MAX_INFLIGHT_BLOCKS) {
      int64_t start = 0, end = 0;
      if (!pickNextBlock(start, end)) {
        break;
      }
      batch.push_back({start, end});
    }
    if (batch.empty()) {
      break;
    }

    // OP_REQUESTPARTS payload: [16B hash][3 x start][3 x end]
    // (4-byte offsets; 8-byte for the I64 variant). Unused slots are zero.
    std::vector<unsigned char> rawHash = rawFileHash_;
    if (rawHash.size() != 16) {
      throw DL_ABORT_EX2("Invalid ED2K file hash for parts request",
                         error_code::UNKNOWN_ERROR);
    }
    std::vector<unsigned char> payload;
    payload.insert(payload.end(), rawHash.begin(), rawHash.end());

    if (useI64Requests_) {
      for (size_t i = 0; i < BLOCKS_PER_MESSAGE; ++i) {
        appendLe64(payload, i < batch.size()
                                ? static_cast<uint64_t>(batch[i].start)
                                : 0);
      }
      for (size_t i = 0; i < BLOCKS_PER_MESSAGE; ++i) {
        appendLe64(payload, i < batch.size()
                                ? static_cast<uint64_t>(batch[i].end)
                                : 0);
      }
    }
    else {
      for (size_t i = 0; i < BLOCKS_PER_MESSAGE; ++i) {
        appendLe32(payload, i < batch.size()
                                ? static_cast<uint32_t>(batch[i].start)
                                : 0);
      }
      for (size_t i = 0; i < BLOCKS_PER_MESSAGE; ++i) {
        appendLe32(payload, i < batch.size()
                                ? static_cast<uint32_t>(batch[i].end)
                                : 0);
      }
    }

    queueMessage(useI64Requests_ ? ed2kop::REQUEST_PARTS_I64
                                 : ed2kop::REQUEST_PARTS,
                 payload.data(), payload.size());

    // Record the blocks as in flight BEFORE flushing: even on EAGAIN the
    // queued message will eventually go out.
    for (const auto& b : batch) {
      inflightBlocks_.push_back(b);
    }

    A2_LOG_DEBUG(fmt("CUID#%" PRId64 " - ED2K requesting %zu blocks"
                     " [%lld, %lld)%s",
                     getCuid(), batch.size(),
                     static_cast<long long>(batch.front().start),
                     static_cast<long long>(batch.back().end),
                     useI64Requests_ ? " (I64)" : ""));

    if (!flushSendBuffer()) {
      // EAGAIN or error — caller decides (connectionError_ is set on
      // real errors).
      return false;
    }
  }
  return true;
}

// Return the lowest offset in [from, limit) that is neither written nor
// already in flight. writtenRanges_ and inflightBlocks_ are both sorted.
int64_t Ed2kDownloadCommand::nextFreeOffset(int64_t from, int64_t limit) const
{
  int64_t next = from;
  bool moved = true;
  while (moved && next < limit) {
    moved = false;
    for (const auto& r : writtenRanges_) {
      if (r.start <= next && next < r.end) {
        next = r.end;
        moved = true;
      }
    }
    for (const auto& b : inflightBlocks_) {
      if (b.start <= next && next < b.end) {
        next = b.end;
        moved = true;
      }
    }
  }
  return next;
}

bool Ed2kDownloadCommand::pickNextBlock(int64_t& start, int64_t& end)
{
  if (fileSize_ == 0) {
    return false;
  }

  int partIdx = parts_.empty() ? -1 : findBestPartToDownload(currentSourceIndex_);
  if (!parts_.empty() && partIdx < 0) {
    // Every incomplete part is unavailable from this peer (or fully
    // covered by in-flight requests).
    return false;
  }

  int64_t base = 0;
  int64_t limit = static_cast<int64_t>(fileSize_);
  if (partIdx >= 0) {
    auto& part = parts_[partIdx];
    base = part.offset;
    limit = part.offset + part.length;
    part.downloading = true;
    part.lastRequested.reset();
  }

  int64_t next = nextFreeOffset(base, limit);
  if (next >= limit) {
    return false;
  }

  start = next;
  end = std::min(next + ED2K_BLOCK_SIZE, limit);
  downloadOffset_ = end; // informational cursor
  return true;
}

bool Ed2kDownloadCommand::handleSendingPart(
    const std::vector<unsigned char>& payload, bool is64)
{
  // OP_SENDINGPART:     [16B hash][4B start][4B end][data]
  // OP_SENDINGPART_I64: [16B hash][8B start][8B end][data]
  const size_t headerLen = is64 ? 32 : 24;
  if (payload.size() < headerLen) {
    A2_LOG_WARN(fmt("CUID#%" PRId64 " - ED2K SENDING_PART too short"
                    " (%zu bytes), dropping peer", getCuid(), payload.size()));
    tryNextPeer();
    return false;
  }

  // The data must belong to our file.
  std::vector<unsigned char> rawHash = rawFileHash_;
  if (rawHash.size() == 16 &&
      memcmp(payload.data(), rawHash.data(), 16) != 0) {
    A2_LOG_WARN(fmt("CUID#%" PRId64 " - ED2K SENDING_PART hash mismatch,"
                    " dropping peer", getCuid()));
    // A peer sending data for a different file hash is either malicious
    // or corrupted — permanently exclude it so it isn't retried.
    if (currentSourceIndex_ < sources_.size()) {
      markPeerFailed(sources_[currentSourceIndex_].addr,
                     sources_[currentSourceIndex_].port, true);
    }
    tryNextPeer();
    return false;
  }

  int64_t dataStart = 0, dataEnd = 0;
  if (is64) {
    dataStart = static_cast<int64_t>(readLe64(payload.data() + 16));
    dataEnd = static_cast<int64_t>(readLe64(payload.data() + 24));
  }
  else {
    dataStart = static_cast<int64_t>(readLe32(payload.data() + 16));
    dataEnd = static_cast<int64_t>(readLe32(payload.data() + 20));
  }

  if (dataEnd <= dataStart ||
      dataEnd - dataStart > ED2K_BLOCK_SIZE ||
      dataEnd > static_cast<int64_t>(fileSize_) ||
      payload.size() < headerLen + static_cast<size_t>(dataEnd - dataStart)) {
    A2_LOG_WARN(fmt("CUID#%" PRId64 " - ED2K SENDING_PART malformed range"
                    " [%lld, %lld), dropping peer",
                    getCuid(), static_cast<long long>(dataStart),
                    static_cast<long long>(dataEnd)));
    tryNextPeer();
    return false;
  }

  // Match against an in-flight block (peers answer requests in order but
  // may split a requested block into smaller messages).
  size_t matchIdx = inflightBlocks_.size();
  for (size_t i = 0; i < inflightBlocks_.size(); ++i) {
    const auto& b = inflightBlocks_[i];
    if (b.start <= dataStart && dataEnd <= b.end) {
      matchIdx = i;
      break;
    }
  }
  if (matchIdx == inflightBlocks_.size()) {
    // Unsolicited or duplicate block — tolerate (do not write).
    A2_LOG_DEBUG(fmt("CUID#%" PRId64 " - ED2K: ignoring unexpected block"
                     " [%lld, %lld)",
                     getCuid(), static_cast<long long>(dataStart),
                     static_cast<long long>(dataEnd)));
    return true;
  }

  // Shrink/split/remove the matched in-flight entry.
  {
    BlockRequest b = inflightBlocks_[matchIdx];
    inflightBlocks_.erase(inflightBlocks_.begin() + matchIdx);
    if (dataStart > b.start) {
      inflightBlocks_.insert(inflightBlocks_.begin() + matchIdx,
                             {b.start, dataStart});
      ++matchIdx;
    }
    if (dataEnd < b.end) {
      inflightBlocks_.insert(inflightBlocks_.begin() + matchIdx,
                             {dataEnd, b.end});
    }
  }

  const unsigned char* fileData = payload.data() + headerLen;
  size_t dataLen = static_cast<size_t>(dataEnd - dataStart);

  A2_LOG_DEBUG(fmt("CUID#%" PRId64 " - ED2K received block [%lld, %lld)",
                   getCuid(), static_cast<long long>(dataStart),
                   static_cast<long long>(dataEnd)));

  // Duplicate data (already covered) is skipped, not re-written.
  if (!isRangeCovered(dataStart, dataEnd)) {
    if (!writeBlockToDisk(dataStart, fileData, dataLen)) {
      throw DL_ABORT_EX2("ED2K failed to write block to disk",
                         error_code::FILE_IO_ERROR);
    }
    recordWrittenRange(dataStart, dataEnd);
    downloadedLength_ += static_cast<int64_t>(dataLen);

    // Proof-by-transfer: this source demonstrably has the part.
    if (!parts_.empty() && currentSourceIndex_ < sources_.size()) {
      size_t pidx = partIndexForOffset(dataStart);
      auto& src = sources_[currentSourceIndex_];
      if (src.availableParts.empty()) {
        src.availableParts.assign(parts_.size(), false);
      }
      if (pidx < src.availableParts.size()) {
        src.availableParts[pidx] = true;
      }
      if (pidx < parts_.size()) {
        auto& srcs = parts_[pidx].sources;
        if (std::find(srcs.begin(), srcs.end(), currentSourceIndex_) ==
            srcs.end()) {
          srcs.push_back(currentSourceIndex_);
        }
      }
      updatePartCompletion();
    }

    // Feed download-speed statistics.
    auto dc = getDownloadContext();
    if (dc) {
      dc->updateDownload(dataLen);
    }
  }

  if (currentSourceIndex_ < sources_.size()) {
    sources_[currentSourceIndex_].lastActive.reset();
  }
  getCheckPoint().reset();
  return true;
}

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

void Ed2kDownloadCommand::recordWrittenRange(int64_t start, int64_t end)
{
  // Insert [start, end) into writtenRanges_, merging overlapping or
  // adjacent entries so the set stays sorted and non-overlapping.
  size_t i = 0;
  while (i < writtenRanges_.size() && writtenRanges_[i].end < start) {
    ++i;
  }
  int64_t mergedStart = start;
  int64_t mergedEnd = end;
  size_t j = i;
  while (j < writtenRanges_.size() && writtenRanges_[j].start <= mergedEnd) {
    mergedStart = std::min(mergedStart, writtenRanges_[j].start);
    mergedEnd = std::max(mergedEnd, writtenRanges_[j].end);
    ++j;
  }
  writtenRanges_.erase(writtenRanges_.begin() + i,
                       writtenRanges_.begin() + j);
  writtenRanges_.insert(writtenRanges_.begin() + i, {mergedStart, mergedEnd});

  // Advance the truthful prefix in PieceStorage — but never mark the final
  // piece: that happens in verifyHash() after the MD4 tree check passes.
  int64_t prefix = prefixLength();
  if (prefix > lastMarkedLength_) {
    int64_t markLen = prefix;
    if (markLen >= static_cast<int64_t>(fileSize_)) {
      markLen = static_cast<int64_t>(fileSize_) - 1;
    }
    if (markLen > 0) {
      try {
        auto ps = getRequestGroup()->getPieceStorage();
        auto dc = getDownloadContext();
        if (ps && dc && dc->getPieceLength() > 0) {
          size_t pieceLen = dc->getPieceLength();
          if (static_cast<int64_t>(lastMarkedLength_ / pieceLen) <
              markLen / static_cast<int64_t>(pieceLen)) {
            ps->markPiecesDone(markLen);
            lastMarkedLength_ = markLen;
          }
        }
      }
      catch (RecoverableException& e) {
        A2_LOG_DEBUG(fmt("CUID#%" PRId64 " - ED2K: markPiecesDone failed: %s",
                         getCuid(), e.what()));
      }
    }
  }
}

int64_t Ed2kDownloadCommand::prefixLength() const
{
  if (writtenRanges_.empty() || writtenRanges_.front().start != 0) {
    return 0;
  }
  return writtenRanges_.front().end;
}

bool Ed2kDownloadCommand::isRangeCovered(int64_t start, int64_t end) const
{
  for (const auto& r : writtenRanges_) {
    if (r.start > start) {
      break;
    }
    if (r.start <= start && r.end >= end) {
      return true;
    }
  }
  return false;
}

bool Ed2kDownloadCommand::downloadComplete() const
{
  return fileSize_ > 0 &&
         prefixLength() >= static_cast<int64_t>(fileSize_);
}

// ============================================================================
// Whole-file hash verification (VERIFY_HASH state)
// ============================================================================

bool Ed2kDownloadCommand::verifyHash()
{
  if (!verifyStarted_) {
    md4PartCtx_ = make_unique<Ed2kMd4>();
    partHashes_.clear();
    verifyOffset_ = 0;
    verifyPartStart_ = 0;
    verifyStarted_ = true;
    A2_LOG_INFO(fmt("CUID#%" PRId64 " - ED2K: starting MD4 tree verification"
                    " for %" PRId64 " bytes",
                    getCuid(), static_cast<int64_t>(fileSize_)));
  }

  auto ps = getRequestGroup()->getPieceStorage();
  if (!ps || !ps->getDiskAdaptor()) {
    throw DL_ABORT_EX2("ED2K: no disk adaptor for verification",
                       error_code::FILE_IO_ERROR);
  }

  // Process one chunk per tick to keep the event loop responsive.
  const int64_t chunkSize = VERIFY_CHUNK;
  int64_t remaining =
      static_cast<int64_t>(fileSize_) - verifyOffset_;
  size_t toRead = static_cast<size_t>(std::min(chunkSize, remaining));

  if (toRead > 0) {
    std::vector<unsigned char> buf(toRead);
    ssize_t n = ps->getDiskAdaptor()->readData(buf.data(), toRead,
                                               verifyOffset_);
    if (n <= 0) {
      throw DL_ABORT_EX2("ED2K: failed to read file for verification",
                         error_code::FILE_IO_ERROR);
    }

    // Feed the data through per-part MD4 contexts.
    size_t consumed = 0;
    while (consumed < static_cast<size_t>(n)) {
      int64_t partEnd = verifyPartStart_ + partSize_;
      size_t avail = static_cast<size_t>(
          std::min(static_cast<int64_t>(n) - static_cast<int64_t>(consumed),
                   partEnd - verifyOffset_));
      md4PartCtx_->update(buf.data() + consumed, avail);
      verifyOffset_ += static_cast<int64_t>(avail);
      consumed += avail;

      if (verifyOffset_ == partEnd) {
        unsigned char digest[16];
        md4PartCtx_->final(digest);
        partHashes_.insert(partHashes_.end(), digest, digest + 16);
        verifyPartStart_ = partEnd;
      }
    }
    getCheckPoint().reset();
  }

  if (verifyOffset_ < static_cast<int64_t>(fileSize_)) {
    return false; // more to read next tick
  }

  // Finalize a trailing partial part (file smaller than one part, or the
  // file size is not an exact multiple of the part size).
  if (verifyPartStart_ < static_cast<int64_t>(fileSize_)) {
    unsigned char digest[16];
    md4PartCtx_->final(digest);
    partHashes_.insert(partHashes_.end(), digest, digest + 16);
    verifyPartStart_ = static_cast<int64_t>(fileSize_);
  }

  // ED2K file hash: MD4 of concatenated part hashes when there is more
  // than one part; otherwise the single part hash itself.
  std::string computed;
  size_t numParts = partHashes_.size() / 16;
  if (numParts <= 1) {
    computed = Ed2kHelper::hashToHex(partHashes_.data(), partHashes_.size());
  }
  else {
    computed = Ed2kHelper::computeMd4(partHashes_.data(), partHashes_.size());
  }

  if (computed != fileHash_) {
    A2_LOG_ERROR(fmt("CUID#%" PRId64 " - ED2K: hash verification FAILED"
                     " (expected %s, got %s)",
                     getCuid(), fileHash_.c_str(), computed.c_str()));
    throw DL_ABORT_EX2("ED2K file hash verification failed — downloaded"
                       " data is corrupt",
                       error_code::CHECKSUM_ERROR);
  }

  A2_LOG_INFO(fmt("CUID#%" PRId64 " - ED2K: hash verification passed (%s)",
                  getCuid(), computed.c_str()));

  // Integrity confirmed — now it is safe to report completion.
  try {
    ps->markAllPiecesDone();
  }
  catch (RecoverableException& e) {
    A2_LOG_DEBUG(fmt("CUID#%" PRId64 " - ED2K: markAllPiecesDone failed: %s",
                     getCuid(), e.what()));
  }
  return true;
}

// ============================================================================
// Source management helpers
// ============================================================================

void Ed2kDownloadCommand::markPeerFailed(const std::string& addr,
                                         uint16_t port, bool permanent)
{
  for (auto& s : sources_) {
    if (s.addr == addr && s.port == port) {
      s.state = permanent ? SourceState::EXPIRED : SourceState::FAILED;
      s.lastActive.reset();
      break;
    }
  }

  // EXPIRED entries stay in the pool (skipped by tryNextPeer); evicting
  // them would shift indices and confuse the peer iteration logic.

  // Record for cooldown tracking.
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

  // Prune expired entries. Keep permanent failures (they must never be
  // retried); only drop temporary ones whose cooldown has elapsed.
  auto now = global::wallclock();
  failedPeers_.erase(
      std::remove_if(failedPeers_.begin(), failedPeers_.end(),
                     [&now](const FailedPeer& p) {
                       return !p.permanent &&
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
      if (fp.permanent) {
        return true;
      }
      return fp.failTime.difference(now) <
             std::chrono::seconds(PEER_COOLDOWN_SECONDS);
    }
  }
  return false;
}

bool Ed2kDownloadCommand::addSource(const std::string& addr, uint16_t port)
{
  if (addr.empty() || port == 0) {
    return false;
  }
  if (static_cast<int>(sources_.size()) >= maxSources_) {
    return false;
  }

  for (const auto& s : sources_) {
    if (s.addr == addr && s.port == port) {
      return false;
    }
  }

  if (isPeerInCooldown(addr, port)) {
    return false;
  }

  PeerSource ps;
  ps.addr = addr;
  ps.port = port;
  ps.state = SourceState::NEW;
  sources_.push_back(ps);
  return true;
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
  // Aggressive when sources are scarce, relaxed when plentiful.
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
  std::vector<unsigned char> hashBytes = rawFileHash_;
  if (hashBytes.size() != 16) {
    return;
  }

  // OP_REQUESTSOURCES (0x81, eMule protocol 0xC5): [16B file hash]
  queueMessage(ed2kop::REQUEST_SOURCES, hashBytes.data(), hashBytes.size(),
               ED2K_PROT_EMULE);
  sourceExchangeSent_ = true;
  sourceExchangeTimer_.reset();

  A2_LOG_DEBUG(fmt("CUID#%" PRId64 " - ED2K: sent source exchange request",
                   getCuid()));
}

size_t Ed2kDownloadCommand::parseSourcesAnswer(
    const std::vector<unsigned char>& payload)
{
  // OP_ANSWERSOURCES (0x82):  [16B hash][count][entries]
  // OP_ANSWERSOURCES2 (0x84): [1B version][16B hash][count][entries]
  // Entry layouts vary: classic = 6B (4B id + 2B port), eMule = 12B
  // (+ 4B server ip + 2B server port). Parse adaptively: find the count
  // field (1 or 2 bytes) such that the remaining bytes divide evenly.
  for (size_t base : {size_t(0), size_t(1)}) {
    if (payload.size() < base + 17) {
      continue;
    }
    for (int countBytes = 1; countBytes <= 2; ++countBytes) {
      size_t countOff = base + 16;
      if (payload.size() < countOff + static_cast<size_t>(countBytes)) {
        break;
      }
      size_t count = countBytes == 1
                         ? payload[countOff]
                         : readLe16(payload.data() + countOff);
      if (count == 0 || count > 500) {
        continue;
      }
      size_t entriesOff = countOff + countBytes;
      size_t remaining = payload.size() - entriesOff;
      if (remaining == 0 || remaining % count != 0) {
        continue;
      }
      size_t entrySize = remaining / count;
      if (entrySize < 6) {
        continue;
      }

      size_t added = 0;
      for (size_t i = 0; i < count; ++i) {
        const unsigned char* entry = payload.data() + entriesOff + i * entrySize;
        uint32_t id = readLe32(entry);
        uint16_t port = readLe16(entry + 4);
        if (id < 0x01000000 || port == 0) {
          continue; // LowID or invalid
        }
        if (addSource(ipFromWire(entry), port)) {
          ++added;
        }
      }
      if (added > 0) {
        A2_LOG_INFO(fmt("CUID#%" PRId64
                        " - ED2K: source exchange added %zu sources"
                        " (total %zu)",
                        getCuid(), added, sources_.size()));
      }
      return added;
    }
  }
  return 0;
}

void Ed2kDownloadCommand::checkServerSourceRefresh()
{
  if (!serverSourceEnabled_) {
    return;
  }
  if (static_cast<int>(sources_.size()) >= maxSources_) {
    return;
  }
  if (countActiveSources() >= 5) {
    return;
  }

  if (serverSourceRefreshTimer_.difference() >
      std::chrono::seconds(SERVER_SOURCE_REFRESH_SECONDS)) {
    A2_LOG_INFO(fmt("CUID#%" PRId64
                    " - ED2K: periodic server source refresh triggered"
                    " (active sources: %d)",
                    getCuid(), countActiveSources()));
    serverSourceRefreshTimer_.reset();
    resetPeerState();
    loginSent_ = false;
    sourcesRequested_ = false;
    state_ = Ed2kState::SERVER_CONNECT;
  }
}

// ============================================================================
// Context attribute update (for RPC getPeers)
// ============================================================================

void Ed2kDownloadCommand::updateContextAttribute()
{
  auto dc = getDownloadContext();
  if (!dc) return;

  std::shared_ptr<Ed2kContextAttribute> attr;
  if (dc->hasAttribute(CTX_ATTR_ED2K)) {
    attr = std::dynamic_pointer_cast<Ed2kContextAttribute>(
        dc->getAttribute(CTX_ATTR_ED2K));
  }
  if (!attr) {
    attr = std::make_shared<Ed2kContextAttribute>();
    dc->setAttribute(CTX_ATTR_ED2K, attr);
  }

  // Snapshot current sources.
  attr->sources.clear();
  for (const auto& s : sources_) {
    Ed2kSourceInfoRpc info;
    info.addr = s.addr;
    info.port = s.port;
    info.state = static_cast<Ed2kSourceStateRpc>(s.state);
    info.queuePosition = s.queuePosition;
    info.availablePartsCount = 0;
    info.totalPartsCount = static_cast<int>(s.availableParts.size());
    for (bool avail : s.availableParts) {
      if (avail) info.availablePartsCount++;
    }
    attr->sources.push_back(std::move(info));
  }

  // Server info.
  attr->serverAddr = serverAddr_;
  attr->serverPort = serverPort_;

  // KAD state.
  attr->kadEnabled = kadEnabled_;
  switch (kadState_) {
  case KadState::BOOTSTRAP:    attr->kadState = "BOOTSTRAP"; break;
  case KadState::READY:        attr->kadState = "READY"; break;
  case KadState::SEARCHING:    attr->kadState = "SEARCHING"; break;
  case KadState::WAIT_RESPONSE:attr->kadState = "WAIT_RESPONSE"; break;
  case KadState::COMPLETE:     attr->kadState = "COMPLETE"; break;
  }
}

// ============================================================================
// KAD (Kademlia DHT) source lookup via UDP
// ============================================================================

void Ed2kDownloadCommand::initKad()
{
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

  try {
    kadSocket_ = std::make_shared<SocketCore>(SOCK_DGRAM);
    kadSocket_->bindWithFamily(0, AF_INET);
    kadSocket_->setNonBlockingMode();
    kadRefreshTimer_.reset();
    kadBootstrapSent_ = false;
    kadSearchSent_ = false;
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
  if (!kadEnabled_ || !kadSocket_ || kadNodes_.empty()) {
    return;
  }

  // Drain pending UDP responses first.
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
    if (gotResponse) {
      kadRefreshTimer_.reset();
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
      kadState_ = KadState::COMPLETE;
      kadRefreshTimer_.reset();
    }
    break;
  }

  case KadState::COMPLETE: {
    if (kadRefreshTimer_.difference() >
            std::chrono::seconds(KAD_REFRESH_SECONDS) ||
        (countActiveSources() < 5 &&
         kadRefreshTimer_.difference() > std::chrono::seconds(60))) {
      // Rotate to the next node for diversity and start a new round.
      currentKadNodeIndex_++;
      if (currentKadNodeIndex_ >= kadNodes_.size()) {
        currentKadNodeIndex_ = 0;
      }
      kadBootstrapSent_ = false;
      kadSearchSent_ = false;
      kadState_ = KadState::READY;
      kadRefreshTimer_.reset();
    }
    break;
  }
  }
}

void Ed2kDownloadCommand::kadBootstrap()
{
  if (!kadSocket_ || kadNodes_.empty()) {
    return;
  }

  const auto& node = kadNodes_[currentKadNodeIndex_ % kadNodes_.size()];

  // KADEMLIA2_BOOTSTRAP_REQ: [0xE4][0x01][16B client id]
  std::vector<unsigned char> packet;
  packet.push_back(KAD2_PROT);
  packet.push_back(kad2op::BOOTSTRAP_REQ);
  appendUserHash(packet);

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
  if (!kadSocket_ || kadNodes_.empty()) {
    return;
  }

  std::vector<unsigned char> hashBytes = rawFileHash_;
  if (hashBytes.size() != 16) {
    return;
  }

  // Query up to 3 known nodes per round (hello first, then search).
  size_t queried = 0;
  for (size_t i = 0; i < kadNodes_.size() && queried < 3; ++i) {
    const auto& node =
        kadNodes_[(currentKadNodeIndex_ + i) % kadNodes_.size()];

    // KADEMLIA2_HELLO_REQ: [0xE4][0x11][16B id][4B ip][2B udp][2B tcp][1B ver]
    std::vector<unsigned char> hello;
    hello.push_back(KAD2_PROT);
    hello.push_back(kad2op::HELLO_REQ);
    appendUserHash(hello);
    appendLe32(hello, 0);
    appendLe16(hello, 0);
    appendLe16(hello, 0);
    hello.push_back(8); // KAD version

    // KADEMLIA2_SEARCH_SOURCE_REQ:
    //   [0xE4][0x34][16B target id][1B search_type][4B start position]
    std::vector<unsigned char> packet;
    packet.push_back(KAD2_PROT);
    packet.push_back(kad2op::SEARCH_SOURCE_REQ);
    packet.insert(packet.end(), hashBytes.begin(), hashBytes.end());
    packet.push_back(0x00); // search_type = 0 (file/source search)
    appendLe32(packet, 0);  // start position

    try {
      kadSocket_->writeData(hello.data(), hello.size(),
                            node.first, node.second);
      kadSocket_->writeData(packet.data(), packet.size(),
                            node.first, node.second);
      ++queried;
    }
    catch (RecoverableException& e) {
      A2_LOG_DEBUG(fmt("CUID#%" PRId64 " - ED2K: KAD search to %s:%u"
                       " failed: %s",
                       getCuid(), node.first.c_str(), node.second,
                       e.what()));
    }
  }

  if (queried > 0) {
    kadSearchSent_ = true;
    A2_LOG_INFO(fmt("CUID#%" PRId64 " - ED2K: KAD find-source sent to %zu"
                    " nodes for hash %s",
                    getCuid(), queried, fileHash_.c_str()));
  }
}

// Skip one KAD tag list starting at *off. Returns the offset just past the
// list, or SIZE_MAX if the encoding is malformed.
static size_t kadSkipTags(const unsigned char* p, size_t len, size_t off)
{
  if (off >= len) {
    return SIZE_MAX;
  }
  uint8_t tagCount = p[off++];
  for (uint8_t i = 0; i < tagCount; ++i) {
    if (off + 2 > len) {
      return SIZE_MAX;
    }
    uint8_t type = p[off++];
    uint8_t nameLen = p[off++];
    if (off + nameLen > len) {
      return SIZE_MAX;
    }
    off += nameLen;

    size_t valueLen = 0;
    bool fixed = true;
    switch (type) {
    case 0x01: valueLen = 16; break;  // HASH
    case 0x03: valueLen = 4; break;   // UINT32
    case 0x04: valueLen = 4; break;   // FLOAT32
    case 0x05: valueLen = 2; break;  // UINT16
    case 0x06: valueLen = 1; break;  // UINT8 / BOOL
    case 0x08: valueLen = 2; break;  // UINT16
    case 0x09: valueLen = 1; break;  // UINT8
    case 0x0B: valueLen = 8; break;   // UINT64
    case 0x02: {                      // STRING: [1B len][chars]
      if (off + 1 > len) {
        return SIZE_MAX;
      }
      valueLen = 1 + p[off];
      break;
    }
    case 0x07: {                      // BLOB: [4B len][bytes]
      if (off + 4 > len) {
        return SIZE_MAX;
      }
      valueLen = 4 + readLe32(p + off);
      break;
    }
    case 0x0A: {                      // BSOB: [2B len][bytes]
      if (off + 2 > len) {
        return SIZE_MAX;
      }
      valueLen = 2 + readLe16(p + off);
      break;
    }
    default:
      if (type >= 0x0C && type <= 0x1B) {
        // STR1..STR16: implicit length (type - 0x0B) bytes, no length field
        valueLen = type - 0x0B;
      }
      else {
        fixed = false;
      }
      break;
    }
    if (!fixed) {
      return SIZE_MAX;
    }
    if (off + valueLen > len) {
      return SIZE_MAX;
    }
    off += valueLen;
  }
  return off;
}

bool Ed2kDownloadCommand::kadProcessResponse()
{
  if (!kadSocket_) {
    return false;
  }

  unsigned char buf[2048];
  Endpoint sender;

  try {
    ssize_t n = kadSocket_->readDataFrom(buf, sizeof(buf), sender);
    if (n <= 0) {
      return false;
    }

    A2_LOG_DEBUG(fmt("CUID#%" PRId64 " - ED2K: KAD response %zd bytes"
                     " from %s:%u",
                     getCuid(), n, sender.addr.c_str(), sender.port));

    if (n < 2 || buf[0] != KAD2_PROT) {
      return n > 0;
    }

    unsigned char opcode = buf[1];

    if (opcode == kad2op::BOOTSTRAP_RES && n >= 22) {
      // [16B id][2B tcp port][1B version][1B count][25B contacts]
      uint8_t count = buf[21];
      size_t off = 22;
      for (uint8_t i = 0; i < count && off + 25 <= static_cast<size_t>(n);
           ++i, off += 25) {
        // contact: [16B id][4B ip][2B udp port][2B tcp port][1B version]
        const unsigned char* ipBytes = buf + off + 16;
        uint16_t tcpPort = readLe16(buf + off + 22);
        if (tcpPort > 0) {
          std::string ip = ipFromWire(ipBytes);
          bool known = false;
          for (const auto& kn : kadNodes_) {
            if (kn.first == ip && kn.second == tcpPort) {
              known = true;
              break;
            }
          }
          if (!known && kadNodes_.size() < 64) {
            kadNodes_.push_back({ip, tcpPort});
          }
        }
      }
      return true;
    }

    if (opcode == kad2op::SEARCH_RES && n >= 19) {
      // [16B target id][1B answer count][answers]
      // answer: [25B contact][1B type][tag list]
      uint8_t count = buf[18];
      size_t off = 19;
      for (uint8_t i = 0; i < count; ++i) {
        if (off + 26 > static_cast<size_t>(n)) {
          break;
        }
        const unsigned char* ipBytes = buf + off + 16;
        uint16_t tcpPort = readLe16(buf + off + 22);
        off += 25;
        uint8_t answerType = buf[off++];

        if (tcpPort > 0) {
          std::string ip = ipFromWire(ipBytes);
          // Every returned contact is both a potential source and a
          // potential next-hop KAD node.
          addSource(ip, tcpPort);
          bool known = false;
          for (const auto& kn : kadNodes_) {
            if (kn.first == ip && kn.second == tcpPort) {
              known = true;
              break;
            }
          }
          if (!known && kadNodes_.size() < 64) {
            kadNodes_.push_back({ip, tcpPort});
          }
          A2_LOG_INFO(fmt("CUID#%" PRId64 " - ED2K: KAD found contact %s:%u"
                          " (type=%u)",
                          getCuid(), ip.c_str(), tcpPort, answerType));
        }

        // Skip the answer's tag list to reach the next answer.
        size_t next = kadSkipTags(buf, static_cast<size_t>(n), off);
        if (next == SIZE_MAX) {
          break;
        }
        off = next;
      }
      return true;
    }

    if (opcode == kad2op::HELLO_RES && n >= 27) {
      // [16B id][4B ip][2B udp port][2B tcp port][1B version]
      const unsigned char* ipBytes = buf + 2 + 16;
      uint16_t tcpPort = readLe16(buf + 2 + 22);
      if (tcpPort > 0) {
        std::string ip = ipFromWire(ipBytes);
        bool known = false;
        for (const auto& kn : kadNodes_) {
          if (kn.first == ip && kn.second == tcpPort) {
            known = true;
            break;
          }
        }
        if (!known && kadNodes_.size() < 64) {
          kadNodes_.push_back({ip, tcpPort});
        }
      }
      return true;
    }

    return true;
  }
  catch (RecoverableException&) {
    return false;
  }
}

// ============================================================================
// Part Availability Manager
// ============================================================================

void Ed2kDownloadCommand::initParts()
{
  parts_.clear();
  if (partSize_ <= 0 || fileSize_ == 0) {
    return;
  }

  int64_t remaining = static_cast<int64_t>(fileSize_);
  int64_t offset = 0;
  while (remaining > 0) {
    PartInfo p;
    p.offset = offset;
    p.length = std::min(partSize_, remaining);
    p.completed = false;
    p.downloading = false;
    parts_.push_back(p);
    offset += partSize_;
    remaining -= partSize_;
  }

  // Mark parts covered by the resumed prefix.
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

void Ed2kDownloadCommand::updatePartCompletion()
{
  if (parts_.empty() || writtenRanges_.empty()) {
    return;
  }

  // Only inspect parts overlapping the most recently extended range —
  // scanning the whole table per 180KB block is too expensive for
  // multi-GB files.
  const Range& last = writtenRanges_.back();
  size_t firstPart = partIndexForOffset(last.start);
  size_t lastPart = partIndexForOffset(std::max<int64_t>(last.end - 1, 0));
  for (size_t i = firstPart; i <= lastPart && i < parts_.size(); ++i) {
    auto& p = parts_[i];
    if (!p.completed &&
        isRangeCovered(p.offset, p.offset + p.length)) {
      p.completed = true;
      p.downloading = false;
      A2_LOG_DEBUG(fmt("CUID#%" PRId64 " - ED2K: part %zu complete",
                       getCuid(), i));
    }
  }
}

void Ed2kDownloadCommand::updatePartAvailability(
    size_t sourceIndex, const std::vector<bool>& partBitmap)
{
  if (sourceIndex >= sources_.size() || parts_.empty()) {
    return;
  }

  auto& src = sources_[sourceIndex];
  src.availableParts = partBitmap;
  if (src.availableParts.size() > parts_.size()) {
    src.availableParts.resize(parts_.size());
  }

  for (size_t i = 0; i < src.availableParts.size() && i < parts_.size(); ++i) {
    if (src.availableParts[i]) {
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
  if (partSize_ <= 0) {
    return 0;
  }
  return static_cast<size_t>(offset / partSize_);
}

int Ed2kDownloadCommand::findBestPartToDownload(size_t sourceIndex)
{
  if (parts_.empty() || sourceIndex >= sources_.size()) {
    return -1;
  }

  const auto& src = sources_[sourceIndex];
  // An empty bitmap means "availability unknown" — treat as "has all".
  bool hasBitmap = !src.availableParts.empty();

  // Candidates: incomplete, available from this source (if known), and
  // with at least one byte neither written nor in flight.
  std::vector<int> candidates;
  for (size_t i = 0; i < parts_.size(); ++i) {
    if (parts_[i].completed) {
      continue;
    }
    if (hasBitmap && i < src.availableParts.size() &&
        !src.availableParts[i]) {
      continue;
    }
    if (nextFreeOffset(parts_[i].offset,
                       parts_[i].offset + parts_[i].length) >=
        parts_[i].offset + parts_[i].length) {
      continue; // fully written or fully in flight
    }
    candidates.push_back(static_cast<int>(i));
  }

  if (candidates.empty()) {
    return -1;
  }

  // Rarest-first: prefer parts with the fewest known sources. stable_sort
  // keeps part order among equals (sequential behavior when availability
  // is unknown).
  std::stable_sort(candidates.begin(), candidates.end(),
                   [this](int a, int b) {
                     return parts_[a].sources.size() < parts_[b].sources.size();
                   });

  // Among the rarest, prefer parts not requested recently.
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
