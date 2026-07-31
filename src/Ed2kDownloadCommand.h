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
    PEER_SOURCE_EXCHANGE, // Ask connected peer for additional sources
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

  // Source lifecycle state. ED2K heavily depends on peer state because
  // a peer may be queued (upload slot) rather than actively transferring.
  enum class SourceState {
    NEW,         // Newly discovered, not yet processed
    CONNECTING,  // Non-blocking connect in progress
    CONNECTED,   // Hello exchanged but not downloading
    DOWNLOADING, // Actively transferring file data
    QUEUED,      // In peer's upload queue (waiting for a slot)
    FAILED,      // Temporary failure (subject to cooldown)
    EXPIRED      // Permanently failed (e.g. hash mismatch) — never retry
  };

  // KAD (Kademlia DHT) lookup state machine. KAD queries are expensive,
  // so instead of polling on a fixed timer we run a proper state machine:
  // BOOTSTRAP → READY → SEARCHING → WAIT_RESPONSE → COMPLETE.
  enum class KadState {
    BOOTSTRAP,      // Joining the DHT network via a bootstrap node
    READY,          // Bootstrap done (or skipped), ready to search
    SEARCHING,      // KAD_FIND_SOURCE sent, waiting for responses
    WAIT_RESPONSE,  // Grace period to collect delayed responses
    COMPLETE        // Search round done; will retry after refresh timer
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
  // PeerSource is the unit of source management. It carries lifecycle
  // state (SourceState) and, once learned from the peer, which ED2K
  // parts (9.5MB chunks) the peer has. The part bitmap drives the
  // Part Availability Manager so we request data the peer actually owns.
  struct PeerSource {
    std::string addr;
    uint16_t port;
    SourceState state = SourceState::NEW;
    Timer lastActive;
    // Bitmap of available 9.5MB parts. Empty = unknown (treat as "has all").
    // Indexed by part number = floor(offset / ED2K_PART_SIZE).
    std::vector<bool> availableParts;
    int queuePosition = -1; // Peer's upload-queue rank (-1 = not queued)
  };
  std::vector<PeerSource> sources_;
  size_t currentSourceIndex_;

  // --- Source discovery configuration (from options) ---
  bool serverSourceEnabled_;       // PREF_ED2K_SERVER_SOURCE_ENABLED
  bool sourceExchangeEnabled_;     // PREF_ED2K_SOURCE_EXCHANGE_ENABLED
  bool kadEnabled_;                // PREF_ED2K_KAD_ENABLED
  int sourceExchangeInterval_;     // PREF_ED2K_SOURCE_EXCHANGE_INTERVAL (seconds)
  bool sourceExchangeSent_;        // OP_SOURCESREQUEST sent to current peer
  Timer sourceExchangeTimer_;      // Tracks when to request sources again

  // --- Periodic source refresh ---
  Timer serverSourceRefreshTimer_; // When to re-ask server for sources
  static const int SERVER_SOURCE_REFRESH_SECONDS = 120;
  int maxSources_;                 // PREF_ED2K_MAX_SOURCES_PER_FILE cap

  // --- Failed peer tracking (cooldown to avoid retrying dead peers) ---
  // `permanent` distinguishes hard failures (file hash mismatch, banned)
  // from transient ones (timeout, connection refused). Permanent failures
  // are removed from the source pool and never retried.
  struct FailedPeer {
    std::string addr;
    uint16_t port;
    Timer failTime;
    bool permanent = false;
  };
  std::vector<FailedPeer> failedPeers_;
  static const int PEER_COOLDOWN_SECONDS = 300; // 5-minute cooldown

  // --- KAD UDP source lookup ---
  std::shared_ptr<SocketCore> kadSocket_;
  std::vector<std::pair<std::string, uint16_t>> kadNodes_;
  size_t currentKadNodeIndex_;
  Timer kadRefreshTimer_;
  static const int KAD_REFRESH_SECONDS = 180;
  bool kadBootstrapSent_;
  KadState kadState_ = KadState::BOOTSTRAP;

  // --- Part Availability Manager ---
  // ED2K splits a file into 9.5MB PARTs. To download efficiently we must
  // know which parts each peer has, then schedule requests for the rarest
  // incomplete parts first. This avoids every connection hammering the
  // same region (e.g. everyone requesting 0-1GB).
  struct PartInfo {
    int64_t offset = 0;
    int64_t length = 0;
    bool completed = false;
    bool downloading = false;
    Timer lastRequested;
    // Indices into sources_ of peers known to have this part.
    std::vector<size_t> sources;
  };
  std::vector<PartInfo> parts_;
  int64_t partSize_ = 0; // ED2K_PART_SIZE (9.5MB), copied from constant

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
  bool peerSourceExchange();
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

  // --- Source management helpers ---

  // Mark a peer as failed. If `permanent` is true (e.g. file hash
  // mismatch) the peer is removed from the source pool and never retried.
  // Otherwise it enters a cooldown window (PEER_COOLDOWN_SECONDS).
  void markPeerFailed(const std::string& addr, uint16_t port,
                      bool permanent = false);

  // Check if a peer is in cooldown (recently failed, non-permanent).
  bool isPeerInCooldown(const std::string& addr, uint16_t port);

  // Add a source if not duplicate and not in cooldown. Respects maxSources_.
  void addSource(const std::string& addr, uint16_t port);

  // Count sources in active states (CONNECTED/DOWNLOADING/QUEUED).
  int countActiveSources();

  // Dynamic source-exchange interval. Aggressive (60s) when sources are
  // scarce, relaxed (600s) when sources are plentiful, otherwise the
  // user-configured default. See getDynamicExchangeInterval().
  int getDynamicExchangeInterval();

  // Send OP_SOURCESREQUEST to the currently connected peer.
  // Used both in PEER_SOURCE_EXCHANGE state and periodically during
  // PEER_DOWNLOAD to discover new sources.
  void sendSourceExchangeRequest();

  // Parse an OP_SOURCESANSWER payload and add sources.
  // Returns the number of new sources added.
  size_t parseSourcesAnswer(const std::vector<unsigned char>& payload);

  // Periodically refresh sources from server during download.
  // Only triggers when active sources fall below a threshold (5), so
  // popular files with many sources don't waste server queries.
  void checkServerSourceRefresh();

  // --- KAD (Kademlia DHT) source lookup via UDP ---

  // Initialize KAD UDP socket and bootstrap node list.
  void initKad();

  // Drive the KAD state machine (BOOTSTRAP→READY→SEARCHING→
  // WAIT_RESPONSE→COMPLETE). Called from PEER_DOWNLOAD on each tick.
  void kadStateMachine();

  // Send a KAD bootstrap request to the current KAD node.
  void kadBootstrap();

  // Send a KAD_FIND_SOURCE request for the file hash.
  void kadFindSource();

  // Process incoming KAD UDP response (non-blocking).
  // Returns true if a message was processed.
  bool kadProcessResponse();

  // --- Part Availability Manager ---

  // Build the parts_ table from fileSize_ and partSize_. Called once
  // when file size becomes known.
  void initParts();

  // Mark a part as completed (called after a block within the part is
  // fully written). Updates parts_[i].completed and downloadOffset_.
  void markPartCompleted(int64_t offset, int64_t length);

  // Record that a source owns a set of parts. Called after parsing a
  // peer's part-status info (OP_FILESTATUS / hello answer tags).
  void updatePartAvailability(size_t sourceIndex,
                              const std::vector<bool>& partBitmap);

  // Pick the next part to download from the current peer.
  // Prefers incomplete parts the peer has, rarest-first, and avoids
  // parts recently requested. Returns the part index, or -1 if none
  // available (fall back to sequential downloadOffset_).
  int findBestPartToDownload(size_t sourceIndex);

  // Map an absolute file offset to its part index.
  size_t partIndexForOffset(int64_t offset);

  // --- Low-level protocol helpers ---
  void queueMessage(unsigned char msgType, const unsigned char* payload,
                    size_t payloadLen);
  bool flushSendBuffer();
  bool tryReceiveMessage(unsigned char& msgType,
                         std::vector<unsigned char>& payload);
};

} // namespace aria2

#endif // D_ED2K_DOWNLOAD_COMMAND_H
