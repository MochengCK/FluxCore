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

// Ed2kDownloadCommand implements the full eDonkey2000 protocol for
// downloading a file via ED2K links.
//
// The eDonkey protocol is P2P: the server only provides source lists
// (peers who have the file). Actual file data is downloaded from peers.
//
// Flow:
//   1. Connect to server (done by Ed2kInitiateConnectionCommand)
//   2. SERVER_LOGIN: send OP_LOGINREQUEST, receive OP_IDCHANGE
//   3. SERVER_GET_SOURCES: send OP_GETFILESOURCES, receive OP_FOUNDSOURCES
//   4. PEER_CONNECT: establish TCP connection to a peer from the source list
//   5. PEER_HANDSHAKE: send OP_HELLO, receive OP_HELLOANSWER
//   6. PEER_START_UPLOAD: send OP_STARTUPLOADREQ, receive OP_ACCEPTUPLOADREQ
//   7. PEER_DOWNLOAD: send OP_REQUESTPARTS, receive OP_SENDINGPART data
//   8. Write data to disk, update progress, repeat until file complete
class Ed2kDownloadCommand : public AbstractCommand {
public:
  Ed2kDownloadCommand(cuid_t cuid, const std::shared_ptr<Request>& req,
                      const std::shared_ptr<FileEntry>& fileEntry,
                      RequestGroup* requestGroup, DownloadEngine* e,
                      const std::shared_ptr<SocketCore>& s);

  virtual ~Ed2kDownloadCommand();

  virtual bool execute() CXX11_OVERRIDE;

  void setFileHash(const std::string& hash);
  void setFileSize(uint64_t size);
  void setServerAddr(const std::string& addr, uint16_t port);

protected:
  virtual bool executeInternal() CXX11_OVERRIDE;

private:
  // Main protocol states. The command transitions through these states
  // sequentially: server phase (login + source discovery) then peer phase
  // (handshake + upload + download).
  enum class Ed2kState {
    SERVER_LOGIN,        // Login to ED2K server
    SERVER_GET_SOURCES,  // Request file sources from server
    PEER_CONNECT,        // Establish TCP connection to a peer
    PEER_HANDSHAKE,      // Exchange hello messages with peer
    PEER_START_UPLOAD,   // Request upload slot from peer
    PEER_DOWNLOAD,       // Download file data from peer
    FINISHED,
    FAILURE
  };

  // Sub-states within PEER_DOWNLOAD. Because the socket is non-blocking,
  // execute() may return false mid-block; these sub-states ensure we
  // resume correctly.
  enum class DownloadSubState {
    REQUEST_PARTS,   // Need to send OP_REQUESTPARTS for current block
    RECEIVING_DATA   // Waiting for OP_SENDINGPART response
  };

  // --- File info ---
  std::string fileHash_;
  uint64_t fileSize_;
  int64_t downloadedLength_;

  // --- State machine ---
  Ed2kState state_;
  DownloadSubState downloadSubState_;

  // --- Server info (for OP_HELLO) ---
  std::string serverAddr_;
  uint16_t serverPort_;

  // --- Source/peer management ---
  struct PeerSource {
    std::string addr;
    uint16_t port;
  };
  std::vector<PeerSource> sources_;
  size_t currentSourceIndex_;

  // --- Download progress ---
  int64_t downloadOffset_;  // Current byte offset in the file
  int64_t lastMarkedLength_;  // Last length passed to markPiecesDone()

  // --- Message-sent flags (prevent re-sending on execute() re-entry) ---
  bool loginSent_;
  bool sourcesRequested_;
  bool helloSent_;
  bool uploadReqSent_;
  bool partsRequested_;

  // --- Persistent I/O buffers (survive across execute() calls) ---
  std::vector<unsigned char> sendBuffer_;
  std::vector<unsigned char> recvBuffer_;

  // --- Current block request info ---
  int64_t requestStart_;
  int64_t requestEnd_;

  // --- Server phase methods ---
  bool serverLogin();
  bool serverGetSources();

  // --- Peer phase methods ---
  bool peerConnect();
  bool peerHandshake();
  bool peerStartUpload();
  bool peerDownload();

  // Advance to the next peer source. If no more sources, transitions
  // to FAILURE state.
  void tryNextPeer();

  // Write received data block to disk at the given offset.
  bool writeBlockToDisk(int64_t offset, const unsigned char* data, size_t len);

  // Update PieceStorage to reflect downloaded bytes (for progress UI).
  void updateProgress();

  // --- Low-level protocol helpers ---
  // Append a complete ED2K message (4-byte LE length + 0xE3 protocol byte
  // + 1-byte type + payload) to sendBuffer_.
  void queueMessage(unsigned char msgType, const unsigned char* payload,
                    size_t payloadLen);
  // Write as much of sendBuffer_ as the socket accepts.
  // Returns true when the buffer is fully flushed.
  bool flushSendBuffer();
  // Read available data into recvBuffer_ and, if a complete message is
  // present, extract it into msgType/payload.
  // Returns true on success, false if no complete message is available yet.
  bool tryReceiveMessage(unsigned char& msgType,
                         std::vector<unsigned char>& payload);
};

} // namespace aria2

#endif // D_ED2K_DOWNLOAD_COMMAND_H
