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
#ifndef D_ED2K_DOWNLOAD_COMMAND_H
#define D_ED2K_DOWNLOAD_COMMAND_H

#include "AbstractCommand.h"

namespace aria2 {

class Ed2kDownloadCommand : public AbstractCommand {
public:
  Ed2kDownloadCommand(cuid_t cuid, const std::shared_ptr<Request>& req,
                      const std::shared_ptr<FileEntry>& fileEntry,
                      RequestGroup* requestGroup, DownloadEngine* e,
                      const std::shared_ptr<SocketCore>& s);

  virtual ~Ed2kDownloadCommand();

  virtual bool execute() CXX11_OVERRIDE;

  // Set file hash and size for ED2K download
  void setFileHash(const std::string& hash);
  void setFileSize(uint64_t size);

protected:
  virtual bool executeInternal() CXX11_OVERRIDE;

private:
  // ED2K download states
  // NOTE: Avoid using ERROR as enum value because windows.h #define ERROR 0
  // which causes compilation failure on MinGW/MSVC.
  enum class Ed2kState {
    HANDSHAKE,
    FILE_INFO,
    DOWNLOADING,
    FINISHED,
    FAILURE
  };

  // Sub-states within the DOWNLOADING phase. Because the socket is
  // non-blocking, execute() may return false mid-chunk; these sub-states
  // ensure we resume correctly without re-sending protocol messages.
  enum class DownloadSubState {
    REQUEST_UPLOAD,      // Need to send START_UPLOAD_REQ for current chunk
    WAIT_ACCEPT_UPLOAD,  // Waiting for ACCEPT_UPLOAD_REQ
    RECEIVING_DATA,      // Receiving SENDING_PART frames for the chunk
    CHUNK_COMPLETE       // Chunk done, advance to next
  };

  std::string fileHash_;
  uint64_t fileSize_;
  int64_t downloadedLength_;
  std::shared_ptr<SocketCore> socket_;
  Ed2kState state_;
  DownloadSubState downloadSubState_;
  int currentChunk_;
  int totalChunks_;
  // Track whether the outgoing request for each phase has been queued,
  // so re-entry into execute() doesn't re-send it and corrupt the stream.
  bool handshakeSent_;
  bool fileRequestSent_;

  // Persistent I/O buffers — survive across execute() calls so that
  // partial reads/writes (EAGAIN) don't desynchronize the protocol stream.
  std::vector<unsigned char> sendBuffer_;
  std::vector<unsigned char> recvBuffer_;
  // Accumulator for the current chunk's data during download.
  std::vector<unsigned char> currentChunkData_;

  bool handshake();
  bool requestFileInfo();
  bool receiveData();
  bool verifyChunkMd4(int chunkIndex, const unsigned char* data, size_t len);
  bool writeChunkToDisk(int chunkIndex, const unsigned char* data, size_t len);

  // Append a complete ED2K message (length + type + payload) to sendBuffer_.
  void queueMessage(unsigned char msgType, const unsigned char* payload,
                    size_t payloadLen);
  // Write as much of sendBuffer_ as the socket accepts. Returns true when
  // the buffer is fully flushed.
  bool flushSendBuffer();
  // Read available data into recvBuffer_ and, if a complete message is
  // present, extract it into msgType/payload. Returns true on success,
  // false if no complete message is available yet.
  bool tryReceiveMessage(unsigned char& msgType,
                         std::vector<unsigned char>& payload);
};

} // namespace aria2

#endif // D_ED2K_DOWNLOAD_COMMAND_H