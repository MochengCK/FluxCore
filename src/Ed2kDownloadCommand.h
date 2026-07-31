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
 * OpenSSL library under certain conditions; described in each
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
#include "wallclock.h"

namespace aria2 {

// Ed2kDownloadCommand implements the full eDonkey2000 protocol for
// downloading a file via ED2K links.
//
// The eDonkey protocol is P2P: the server only provides source lists
// (peers who have the file). Actual file data is downloaded from peers.
//
// State machine flow:
//   1. SERVER_CONNECT: establish TCP connection to an ED2K server
//   2. SERVER_LOGIN: send OP_LOGINREQUEST, receive OP_IDCHANGE
//   3. SERVER_GET_SOURCES: send OP_GETFILESOURCES, receive OP_FOUNDSOURCES
//      - If no sources found, wait and retry (SERVER_WAIT_SOURCES)
//   4. PEER_CONNECT: initiate non-blocking TCP connection to a peer
//   5. PEER_WAIT_CONNECT: wait for the non-blocking connect() to complete
//      (checks isWritable(0), then SO_ERROR to detect connection failure)
//   6. PEER_HANDSHAKE: send OP_HELLO, receive OP_HELLOANSWER
//   7. PEER_START_UPLOAD: send OP_STARTUPLOADREQ, receive OP_ACCEPTUPLOADREQ
//   8. PEER_DOWNLOAD: send OP_REQUESTPARTS, receive OP_SENDINGPART data
//   9. Write data to disk, update progress, repeat until file complete
//
// If all peer sources are exhausted, the command reconnects to the server
// to fetch fresh sources (up to MAX_SERVER_ROUNDS times).
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
  // Set the list of ED2K servers to try (for server reconnection).
  void setServerList(const std::vector<std::pair<std::string, uint16_t>>& servers);

protected:
  virtual bool executeInternal() CXX11_OVERRIDE;

private:
  // Main protocol states.
  enum class Ed2kState {
    SERVER_CONNECT,       // Establish TCP connection to ED2K server
    SERVER_LOGIN,         // Login to ED2K server
    SERVER_GET_SOURCES,   // Request file sources from server
    SERVER_WAIT_SOURCES,  // No sources yet — wait and retry
    PEER_CONNECT,         // Initiate non-blocking TCP connection to a peer
    PEER_WAIT_CONNECT,    // Wait for non-blocking connect() to finish
    PEER_HANDSHAKE,       // Exchange hello messages with peer
    PEER_START_UPLOAD,    // Request upload slot from peer
    PEER_DOWNLOAD,        // Download file data from peer
    FINISHED,
    FAILURE
  };

  // Sub-states within PEER_DOWNLOAD.
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

  // --- Server info ---
  std::string serverAddr_;
  uint16_t serverPort_;
  std::vector<std::pair<std::string, uint16_t>> serverList_;
  size_t currentServerIndex_;
  int serverRound_;          // How many times we've cycled through servers
  static const int MAX_SERVER_ROUNDS = 5;

  // --- Source wait retry ---
  Timer sourceWaitStart_;
  static const int SOURCE_WAIT_SECONDS = 30; // Wait between source requests

  // --- Source/peer management ---
  struct PeerSource {
    std::string addr;
    uint16_t port;
  };
  std::vector<PeerSource> sources_;
  size_t currentSourceIndex_;

  // --- Download progress ---
  int64_t downloadOffset_;
  int64_t lastMarkedLength_;

  // --- Message-sent flags ---
  bool loginSent_;
  bool sourcesRequested_;
  bool helloSent_;
  bool uploadReqSent_;
  bool partsRequested_;

  // Set true when flushSendBuffer() hits a real socket error (not EAGAIN).
  // The state machine checks this to decide whether to switch peer/server.
  bool connectionError_;

  // --- Persistent I/O buffers ---
  std::vector<unsigned char> sendBuffer_;
  std::vector<unsigned char> recvBuffer_;

  // --- Current block request info ---
  int64_t requestStart_;
  int64_t requestEnd_;

  // --- Server phase methods ---
  bool serverConnect();
  bool serverLogin();
  bool serverGetSources();
  bool serverWaitSources();

  // --- Peer phase methods ---
  bool peerConnect();
  bool peerWaitConnect();
  bool peerHandshake();
  bool peerStartUpload();
  bool peerDownload();

  // Advance to the next peer source. If no more sources, reconnects
  // to the server for fresh sources (up to MAX_SERVER_ROUNDS).
  void tryNextPeer();

  // Reconnect to the next server in serverList_ to fetch fresh sources.
  // Returns false if all servers and rounds are exhausted (FAILURE).
  bool reconnectServer();

  // Write received data block to disk at the given offset.
  bool writeBlockToDisk(int64_t offset, const unsigned char* data, size_t len);

  // Update PieceStorage to reflect downloaded bytes (for progress UI).
  void updateProgress();

  // --- Low-level protocol helpers ---
  void queueMessage(unsigned char msgType, const unsigned char* payload,
                    size_t payloadLen);
  bool flushSendBuffer();
  bool tryReceiveMessage(unsigned char& msgType,
                         std::vector<unsigned char>& payload);
};

} // namespace aria2

#endif // D_ED2K_DOWNLOAD_COMMAND_H
