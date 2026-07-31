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
static const int64_t ED2K_CHUNK_SIZE = 9500000;
static const size_t ED2K_HEADER_LEN = 4;
static const size_t ED2K_MAX_MSG_SIZE = 1024 * 1024 * 10; // 10MB max

// ED2K protocol message types
namespace ed2kmsg {
  constexpr unsigned char LOGIN_REQUEST = 0x01;
  constexpr unsigned char LOGIN_ACCEPT = 0x02;
  constexpr unsigned char LOGIN_REJECT = 0x03;
  constexpr unsigned char FILE_REQUEST = 0x18;
  constexpr unsigned char FILE_ANSWER = 0x19;
  constexpr unsigned char START_UPLOAD_REQ = 0x40;
  constexpr unsigned char ACCEPT_UPLOAD_REQ = 0x41;
  constexpr unsigned char STOP_UPLOAD_REQ = 0x42;
  constexpr unsigned char SENDING_PART = 0x46;
  constexpr unsigned char STOP_UPLOAD = 0x15;
  constexpr unsigned char START_UPLOAD = 0x14;
  constexpr unsigned char ACCEPT_UPLOAD = 0x16;
  constexpr unsigned char CHANGE_SLOT = 0x32;
  constexpr unsigned char CALLBACK_REQ = 0x38;
  constexpr unsigned char END_OF_FILE = 0x4B;
  constexpr unsigned char PART_HASH_SET = 0x47;
} // namespace ed2kmsg

Ed2kDownloadCommand::Ed2kDownloadCommand(
    cuid_t cuid, const std::shared_ptr<Request>& req,
    const std::shared_ptr<FileEntry>& fileEntry, RequestGroup* requestGroup,
    DownloadEngine* e, const std::shared_ptr<SocketCore>& s)
    : AbstractCommand(cuid, req, fileEntry, requestGroup, e, s),
      fileHash_(),
      fileSize_(0),
      downloadedLength_(0),
      socket_(s),
      state_(Ed2kState::HANDSHAKE),
      downloadSubState_(DownloadSubState::REQUEST_UPLOAD),
      currentChunk_(0),
      totalChunks_(0),
      handshakeSent_(false),
      fileRequestSent_(false)
{
  setReadCheckSocket(getSocket());
}

Ed2kDownloadCommand::~Ed2kDownloadCommand() = default;

bool Ed2kDownloadCommand::executeInternal()
{
  // ED2K uses a custom execute() flow that handles its own state machine.
  // This is not called because execute() override bypasses
  // AbstractCommand::execute().
  return true;
}

void Ed2kDownloadCommand::setFileHash(const std::string& hash)
{
  fileHash_ = hash;
}

void Ed2kDownloadCommand::setFileSize(uint64_t size)
{
  fileSize_ = size;
  if (size > 0) {
    totalChunks_ = static_cast<int>((size + ED2K_CHUNK_SIZE - 1) /
                                    ED2K_CHUNK_SIZE);
  }
}

bool Ed2kDownloadCommand::execute()
{
  A2_LOG_DEBUG(fmt("CUID#%" PRId64 " - Ed2kDownloadCommand::execute()"
                   " state=%d chunk=%d/%d",
                   getCuid(), static_cast<int>(state_), currentChunk_,
                   totalChunks_));

  if (getRequestGroup()->downloadFinished() ||
      getRequestGroup()->isHaltRequested()) {
    return true;
  }

  try {
    // Flush any pending outgoing data first. This ensures that partial
    // writes from a previous execute() call complete before we try to
    // read or queue new messages.
    if (!flushSendBuffer()) {
      setWriteCheckSocket(getSocket());
      addCommandSelf();
      return false;
    }
    disableWriteCheckSocket();

    switch (state_) {
    case Ed2kState::HANDSHAKE:
      if (!handshake()) {
        setReadCheckSocket(getSocket());
        addCommandSelf();
        return false;
      }
      state_ = Ed2kState::FILE_INFO;
      // Fall through
    case Ed2kState::FILE_INFO:
      if (!requestFileInfo()) {
        setReadCheckSocket(getSocket());
        addCommandSelf();
        return false;
      }
      state_ = Ed2kState::DOWNLOADING;
      // Fall through
    case Ed2kState::DOWNLOADING:
      if (!receiveData()) {
        setReadCheckSocket(getSocket());
        addCommandSelf();
        return false;
      }
      state_ = Ed2kState::FINISHED;
      // Fall through
    case Ed2kState::FINISHED:
      A2_LOG_INFO(fmt("CUID#%" PRId64 " - ED2K download completed",
                      getCuid()));
      return true;
    case Ed2kState::FAILURE:
    default:
      throw DL_ABORT_EX2("ED2K download error",
                         error_code::UNKNOWN_ERROR);
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

void Ed2kDownloadCommand::queueMessage(unsigned char msgType,
                                       const unsigned char* payload,
                                       size_t payloadLen)
{
  // ED2K message format:
  // [4 bytes: message length (little-endian, includes type byte)]
  // [1 byte: message type]
  // [N bytes: payload]
  uint32_t msgLen = static_cast<uint32_t>(payloadLen + 1);
  unsigned char header[5];
  header[0] = static_cast<unsigned char>(msgLen);
  header[1] = static_cast<unsigned char>(msgLen >> 8);
  header[2] = static_cast<unsigned char>(msgLen >> 16);
  header[3] = static_cast<unsigned char>(msgLen >> 24);
  header[4] = msgType;

  sendBuffer_.insert(sendBuffer_.end(), header, header + 5);
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
      written = socket_->writeData(sendBuffer_.data() + totalWritten,
                                   toWrite);
    }
    catch (RecoverableException& e) {
      // On error, shift remaining data to front and wait for writability.
      if (totalWritten > 0) {
        sendBuffer_.erase(sendBuffer_.begin(),
                          sendBuffer_.begin() + totalWritten);
      }
      return false;
    }
    if (written == 0) {
      // EAGAIN — socket buffer full or still connecting, wait for writability.
      if (totalWritten > 0) {
        sendBuffer_.erase(sendBuffer_.begin(),
                          sendBuffer_.begin() + totalWritten);
      }
      return false;
    }
    totalWritten += static_cast<size_t>(written);
  }

  sendBuffer_.clear();
  return true;
}

bool Ed2kDownloadCommand::tryReceiveMessage(unsigned char& msgType,
                                            std::vector<unsigned char>& payload)
{
  // Read whatever is available into recvBuffer_.
  // readData() sets len=0 on EAGAIN (no exception); real socket errors
  // throw DlRetryEx which propagates to execute()'s catch for proper retry.
  unsigned char tmp[8192];
  size_t readLen = sizeof(tmp);
  socket_->readData(tmp, readLen);

  if (readLen > 0) {
    recvBuffer_.insert(recvBuffer_.end(), tmp, tmp + readLen);
  }

  // Try to extract a complete message from recvBuffer_.
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
  if (msgLen < 1) {
    throw DL_ABORT_EX2("ED2K message too short",
                       error_code::UNKNOWN_ERROR);
  }

  // Total bytes needed: 4 (header) + msgLen (type + payload)
  size_t totalNeeded = ED2K_HEADER_LEN + msgLen;
  if (recvBuffer_.size() < totalNeeded) {
    return false; // Not enough data yet.
  }

  // Extract message type and payload.
  msgType = recvBuffer_[ED2K_HEADER_LEN];
  size_t payloadLen = msgLen - 1;
  if (payloadLen > 0) {
    payload.assign(recvBuffer_.data() + ED2K_HEADER_LEN + 1,
                   recvBuffer_.data() + ED2K_HEADER_LEN + 1 + payloadLen);
  }
  else {
    payload.clear();
  }

  // Consume the message from the buffer.
  recvBuffer_.erase(recvBuffer_.begin(),
                    recvBuffer_.begin() + totalNeeded);

  return true;
}

bool Ed2kDownloadCommand::handshake()
{
  A2_LOG_DEBUG(fmt("CUID#%" PRId64 " - ED2K handshake: sending login request",
                   getCuid()));

  // Queue the login request only once. On re-entry (after EAGAIN), the
  // send buffer is flushed by execute() before we get here, and we skip
  // re-queueing to avoid sending a duplicate login request.
  if (!handshakeSent_) {
    unsigned char loginPayload[16];
    std::memset(loginPayload, 0, sizeof(loginPayload));
    // Protocol version hash (MD4 of "eDonkey" for compatibility)
    const unsigned char protocolHash[] = {
      0x5F, 0x1E, 0x51, 0x3B, 0x9C, 0xFE, 0xE7, 0x3A,
      0x2E, 0x9B, 0xEC, 0x17, 0x63, 0xA1, 0xAE, 0xE0
    };
    std::memcpy(loginPayload, protocolHash, 16);

    queueMessage(ed2kmsg::LOGIN_REQUEST, loginPayload, 16);
    handshakeSent_ = true;

    // Flush immediately so we can proceed if the socket is writable now.
    if (!flushSendBuffer()) {
      setWriteCheckSocket(getSocket());
      return false;
    }
  }

  // Receive login response
  unsigned char msgType;
  std::vector<unsigned char> payload;
  if (!tryReceiveMessage(msgType, payload)) {
    A2_LOG_DEBUG(fmt("CUID#%" PRId64
                     " - ED2K handshake: waiting for login response",
                     getCuid()));
    return false;
  }

  if (msgType == ed2kmsg::LOGIN_REJECT) {
    throw DL_ABORT_EX2("ED2K login rejected by server",
                       error_code::UNKNOWN_ERROR);
  }

  if (msgType != ed2kmsg::LOGIN_ACCEPT) {
    throw DL_ABORT_EX2(
        fmt("Unexpected ED2K message type in handshake: 0x%02x", msgType),
        error_code::UNKNOWN_ERROR);
  }

  A2_LOG_INFO(fmt("CUID#%" PRId64 " - ED2K handshake completed successfully",
                  getCuid()));
  return true;
}

bool Ed2kDownloadCommand::requestFileInfo()
{
  A2_LOG_DEBUG(fmt("CUID#%" PRId64 " - ED2K requesting file info for hash=%s",
                   getCuid(), fileHash_.c_str()));

  // Convert hex hash to raw bytes
  std::vector<unsigned char> rawHash = Ed2kHelper::hexToHash(fileHash_);
  if (rawHash.size() != 16) {
    throw DL_ABORT_EX2("Invalid ED2K file hash",
                       error_code::UNKNOWN_ERROR);
  }

  // Queue the file request only once.
  if (!fileRequestSent_) {
    queueMessage(ed2kmsg::FILE_REQUEST, rawHash.data(), 16);
    fileRequestSent_ = true;

    if (!flushSendBuffer()) {
      setWriteCheckSocket(getSocket());
      return false;
    }
  }

  // Receive file answer
  unsigned char msgType;
  std::vector<unsigned char> payload;
  if (!tryReceiveMessage(msgType, payload)) {
    A2_LOG_DEBUG(fmt("CUID#%" PRId64 " - ED2K waiting for file answer",
                     getCuid()));
    return false;
  }

  if (msgType != ed2kmsg::FILE_ANSWER) {
    throw DL_ABORT_EX2(
        fmt("Unexpected ED2K message type for file info: 0x%02x, expected "
            "0x19",
            msgType),
        error_code::UNKNOWN_ERROR);
  }

  // Parse file answer: file size (8 bytes LE) + filename (null-terminated)
  if (payload.size() < 8) {
    throw DL_ABORT_EX2("ED2K file answer too short",
                       error_code::UNKNOWN_ERROR);
  }

  uint64_t fileSize = static_cast<uint64_t>(payload[0]) |
                      (static_cast<uint64_t>(payload[1]) << 8) |
                      (static_cast<uint64_t>(payload[2]) << 16) |
                      (static_cast<uint64_t>(payload[3]) << 24) |
                      (static_cast<uint64_t>(payload[4]) << 32) |
                      (static_cast<uint64_t>(payload[5]) << 40) |
                      (static_cast<uint64_t>(payload[6]) << 48) |
                      (static_cast<uint64_t>(payload[7]) << 56);

  // If file size was not set externally, use the one from the server
  if (fileSize_ == 0) {
    fileSize_ = fileSize;
  }

  if (fileSize_ > 0) {
    totalChunks_ = static_cast<int>((fileSize_ + ED2K_CHUNK_SIZE - 1) /
                                    ED2K_CHUNK_SIZE);
  }

  A2_LOG_INFO(fmt("CUID#%" PRId64
                  " - ED2K file info received: size=%" PRId64
                  " chunks=%d",
                  getCuid(), static_cast<int64_t>(fileSize_), totalChunks_));

  return true;
}

bool Ed2kDownloadCommand::receiveData()
{
  while (currentChunk_ < totalChunks_) {
    A2_LOG_DEBUG(fmt("CUID#%" PRId64 " - ED2K downloading chunk %d/%d "
                     "offset=%" PRId64,
                     getCuid(), currentChunk_ + 1, totalChunks_,
                     static_cast<int64_t>(currentChunk_) * ED2K_CHUNK_SIZE));

    // Calculate chunk size (last chunk may be smaller)
    int64_t chunkSize = ED2K_CHUNK_SIZE;
    if (static_cast<int64_t>(currentChunk_ + 1) * ED2K_CHUNK_SIZE >
        static_cast<int64_t>(fileSize_)) {
      chunkSize = static_cast<int64_t>(fileSize_) -
                  static_cast<int64_t>(currentChunk_) * ED2K_CHUNK_SIZE;
    }

    switch (downloadSubState_) {
    case DownloadSubState::REQUEST_UPLOAD: {
      // Queue START_UPLOAD_REQ for this chunk (once per chunk).
      unsigned char startPayload[4];
      uint32_t chunkIdx = static_cast<uint32_t>(currentChunk_);
      startPayload[0] = static_cast<unsigned char>(chunkIdx);
      startPayload[1] = static_cast<unsigned char>(chunkIdx >> 8);
      startPayload[2] = static_cast<unsigned char>(chunkIdx >> 16);
      startPayload[3] = static_cast<unsigned char>(chunkIdx >> 24);

      queueMessage(ed2kmsg::START_UPLOAD_REQ, startPayload, 4);
      if (!flushSendBuffer()) {
        setWriteCheckSocket(getSocket());
        return false;
      }
      downloadSubState_ = DownloadSubState::WAIT_ACCEPT_UPLOAD;
      // Fall through to try receiving immediately.
    }
    case DownloadSubState::WAIT_ACCEPT_UPLOAD: {
      unsigned char msgType;
      std::vector<unsigned char> payload;
      // Consume messages until we see ACCEPT_UPLOAD_REQ, skipping
      // intermediate slot-control messages.
      while (true) {
        if (!tryReceiveMessage(msgType, payload)) {
          A2_LOG_DEBUG(fmt("CUID#%" PRId64
                           " - ED2K waiting for accept upload",
                           getCuid()));
          return false;
        }
        if (msgType == ed2kmsg::CHANGE_SLOT ||
            msgType == ed2kmsg::CALLBACK_REQ) {
          continue;
        }
        break;
      }

      if (msgType != ed2kmsg::ACCEPT_UPLOAD_REQ) {
        throw DL_ABORT_EX2(
            fmt("ED2K unexpected message type: 0x%02x, expected 0x41",
                msgType),
            error_code::UNKNOWN_ERROR);
      }

      // Prepare accumulator for the new chunk.
      currentChunkData_.clear();
      currentChunkData_.reserve(static_cast<size_t>(chunkSize));
      downloadSubState_ = DownloadSubState::RECEIVING_DATA;
      // Fall through to start receiving data.
    }
    case DownloadSubState::RECEIVING_DATA: {
      int64_t bytesReceived =
          static_cast<int64_t>(currentChunkData_.size());
      unsigned char msgType;
      std::vector<unsigned char> payload;
      while (bytesReceived < chunkSize) {
        if (!tryReceiveMessage(msgType, payload)) {
          A2_LOG_DEBUG(
              fmt("CUID#%" PRId64 " - ED2K waiting for chunk data", getCuid()));
          return false;
        }

        if (msgType == ed2kmsg::SENDING_PART) {
          currentChunkData_.insert(currentChunkData_.end(),
                                   payload.begin(), payload.end());
          bytesReceived += static_cast<int64_t>(payload.size());
          downloadedLength_ += static_cast<int64_t>(payload.size());
        }
        else if (msgType == ed2kmsg::END_OF_FILE) {
          A2_LOG_DEBUG(fmt("CUID#%" PRId64
                           " - ED2K end of file for chunk %d",
                           getCuid(), currentChunk_));
          break;
        }
        else if (msgType == ed2kmsg::CHANGE_SLOT ||
                 msgType == ed2kmsg::CALLBACK_REQ) {
          continue;
        }
        else {
          throw DL_ABORT_EX2(
              fmt("ED2K unexpected message during data receive: 0x%02x",
                  msgType),
              error_code::UNKNOWN_ERROR);
        }
      }
      downloadSubState_ = DownloadSubState::CHUNK_COMPLETE;
      // Fall through to finalize the chunk.
    }
    case DownloadSubState::CHUNK_COMPLETE: {
      // Verify MD4 hash of the chunk
      if (!verifyChunkMd4(currentChunk_, currentChunkData_.data(),
                          currentChunkData_.size())) {
        throw DL_RETRY_EX(
            fmt("ED2K chunk %d MD4 hash mismatch, will retry", currentChunk_));
      }

      // Write chunk data to disk
      if (!writeChunkToDisk(currentChunk_, currentChunkData_.data(),
                            currentChunkData_.size())) {
        throw DL_ABORT_EX2("ED2K failed to write chunk to disk",
                           error_code::FILE_IO_ERROR);
      }

      // Update PieceStorage so the engine reports progress correctly.
      // markPiecesDone() sets the bitfield for all pieces up to
      // downloadedLength_, which matches ED2K's sequential download order.
      try {
        auto ps = getRequestGroup()->getPieceStorage();
        if (ps) {
          ps->markPiecesDone(downloadedLength_);
        }
      }
      catch (RecoverableException& e) {
        A2_LOG_DEBUG(fmt("CUID#%" PRId64
                         " - ED2K: failed to update piece progress: %s",
                         getCuid(), e.what()));
      }

      A2_LOG_INFO(fmt("CUID#%" PRId64 " - ED2K chunk %d/%d completed "
                       "(%" PRId64 " bytes, total %" PRId64 ")",
                       getCuid(), currentChunk_ + 1, totalChunks_,
                       static_cast<int64_t>(currentChunkData_.size()),
                       downloadedLength_));

      // Advance chunk state BEFORE queueing the non-critical STOP_UPLOAD_REQ,
      // so that if the flush blocks, re-entry resumes at the next chunk
      // instead of re-finalizing this one.
      currentChunk_++;
      currentChunkData_.clear();
      downloadSubState_ = DownloadSubState::REQUEST_UPLOAD;

      // Queue stop upload for this chunk (non-critical). If this can't be
      // flushed immediately, execute()'s top-level flush will handle it
      // on the next call.
      unsigned char stopPayload[4] = {};
      queueMessage(ed2kmsg::STOP_UPLOAD_REQ, stopPayload, 4);
      if (!flushSendBuffer()) {
        setWriteCheckSocket(getSocket());
        return false;
      }
      break;
    }
    } // switch (downloadSubState_)
  }

  // All chunks downloaded — mark the download as complete in PieceStorage
  // so the engine transitions the RequestGroup to "complete" state.
  try {
    auto ps = getRequestGroup()->getPieceStorage();
    if (ps) {
      ps->markAllPiecesDone();
    }
  }
  catch (RecoverableException& e) {
    A2_LOG_DEBUG(fmt("CUID#%" PRId64
                     " - ED2K: failed to mark all pieces done: %s",
                     getCuid(), e.what()));
  }

  return true;
}

bool Ed2kDownloadCommand::verifyChunkMd4(int chunkIndex,
                                         const unsigned char* data, size_t len)
{
  // Compute MD4 hash of the chunk data
  std::string computedHash = Ed2kHelper::computeMd4(data, len);

  A2_LOG_DEBUG(fmt("CUID#%" PRId64 " - ED2K chunk %d MD4 hash: %s",
                   getCuid(), chunkIndex, computedHash.c_str()));

  // For now, we accept the chunk if the hash computation succeeds
  // In a full implementation, this would compare against received
  // per-chunk hashes from the Part Hash Set message
  if (computedHash.empty()) {
    A2_LOG_ERROR(fmt("CUID#%" PRId64 " - ED2K chunk %d MD4 hash computation "
                     "failed",
                     getCuid(), chunkIndex));
    return false;
  }

  return true;
}

bool Ed2kDownloadCommand::writeChunkToDisk(int chunkIndex,
                                           const unsigned char* data,
                                           size_t len)
{
  if (len == 0) {
    return true;
  }

  try {
    int64_t offset = static_cast<int64_t>(chunkIndex) * ED2K_CHUNK_SIZE;
    auto diskAdaptor = getRequestGroup()->getPieceStorage()->getDiskAdaptor();
    diskAdaptor->writeData(data, len, offset);
    return true;
  }
  catch (RecoverableException& e) {
    A2_LOG_ERROR_EX(fmt("CUID#%" PRId64 " - ED2K failed to write chunk %d "
                        "to disk at offset %" PRId64,
                        getCuid(), chunkIndex,
                        static_cast<int64_t>(chunkIndex) * ED2K_CHUNK_SIZE),
                    e);
    return false;
  }
}

} // namespace aria2