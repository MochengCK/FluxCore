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
 * exception statement from all source files.  If you do not wish to
 * do so, delete this exception statement from all source files.
 */
/* copyright --> */
#ifndef D_ED2K_DOWNLOAD_COMMAND_H
#define D_ED2K_DOWNLOAD_COMMAND_H

#include "AbstractCommand.h"
#include "Ed2kHelper.h"
#include "wallclock.h"

#include <deque>

namespace aria2 {

// Ed2kDownloadCommand implements the eDonkey2000 (ED2K) download protocol.
//
// ED2K is a server-assisted P2P network: ED2K servers only provide source
// lists (peers that have the file); the actual file data is transferred
// between clients directly.
//
// Wire protocol implemented here follows the eMule protocol specification:
//   Client<->Server (protocol byte 0xE3):
//     OP_LOGINREQUEST(0x01) -> OP_IDCHANGE(0x40)
//     OP_GETSOURCES(0x19)   -> OP_FOUNDSOURCES(0x42)
//   Client<->Client (protocol byte 0xE3):
//     OP_HELLO(0x01) -> OP_HELLOANSWER(0x4C)
//     OP_REQUESTFILENAME(0x58) -> OP_REQFILENAMEANSWER(0x59) |
//                                 OP_FILEREQANSNOFIL(0x48)
//     OP_SETREQFILEID(0x4F)    -> OP_FILESTATUS(0x50) [part bitmap]
//     OP_STARTUPLOADREQ(0x54)  -> OP_ACCEPTUPLOADREQ(0x55) |
//                                 OP_QUEUERANK(0x5C)
//     OP_REQUESTPARTS(0x47)    -> OP_SENDINGPART(0x46)
//     64-bit variants for >4GB files: OP_REQUESTPARTS_I64(0xA3),
//     OP_SENDINGPART_I64(0xA2)
//   eMule extension (protocol byte 0xC5):
//     OP_EMULEINFO(0x01) / OP_EMULEINFOANSWER(0x02)
//     OP_REQUESTSOURCES(0x81) -> OP_ANSWERSOURCES(0x82)
//   KAD (UDP, Kademlia2):
//     KADEMLIA2_BOOTSTRAP_REQ(0x01) -> KADEMLIA2_BOOTSTRAP_RES(0x09)
//     KADEMLIA2_SEARCH_SOURCE_REQ(0x34) -> KADEMLIA2_SEARCH_RES(0x3B)
//
// Data integrity: received blocks are tracked in a written-range interval
// set. aria2's PieceStorage bitfield is advanced only by the contiguous
// downloaded prefix, so resume state is always truthful. When the file is
// fully written, its ED2K (MD4 tree) hash is verified against the hash in
// the ed2k:// link before the download is reported complete.
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
    PEER_FILE_INFO,       // Bind file to peer, learn part availability
    PEER_SOURCE_EXCHANGE, // Ask connected peer for additional sources
    PEER_START_UPLOAD,    // Request upload slot from peer
    PEER_DOWNLOAD,        // Download file data from peer
    VERIFY_HASH,          // Whole-file ED2K (MD4 tree) verification
    FINISHED,
    FAILURE
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
    EXPIRED      // Permanently failed (e.g. no file) — never retry
  };

  // KAD (Kademlia DHT) lookup state machine.
  enum class KadState {
    BOOTSTRAP,      // Joining the DHT network via a bootstrap node
    READY,          // Bootstrap done, ready to search
    SEARCHING,      // SEARCH_SOURCE sent, waiting for responses
    WAIT_RESPONSE,  // Grace period to collect delayed responses
    COMPLETE        // Search round done; will retry after refresh timer
  };

  // A contiguous [start, end) byte range written to disk.
  struct Range {
    int64_t start;
    int64_t end;
  };

  // One block request in flight (sent in OP_REQUESTPARTS, awaiting
  // OP_SENDINGPART). Peers answer requests in order.
  struct BlockRequest {
    int64_t start;
    int64_t end;
  };

  // --- File info ---
  std::string fileHash_;
  // Cached 16-byte MD4 hash parsed from fileHash_ in setFileHash(). Avoids
  // re-parsing hex on every hot-path call (handleSendingPart, fillBlockPipeline,
  // etc.) which previously called Ed2kHelper::hexToHash(fileHash_) per block.
  std::vector<unsigned char> rawFileHash_;
  uint64_t fileSize_;
  int64_t downloadedLength_; // total bytes received (for logging)

  // --- State machine ---
  Ed2kState state_;

  // --- Server info ---
  std::string serverAddr_;
  uint16_t serverPort_;
  std::vector<std::pair<std::string, uint16_t>> serverList_;
  size_t currentServerIndex_;
  int serverRound_; // How many times we've cycled through servers
  static const int MAX_SERVER_ROUNDS = 5;

  // --- Source wait retry ---
  Timer sourceWaitStart_;
  static const int SOURCE_WAIT_SECONDS = 30; // Wait between source requests

  // --- Source/peer management ---
  struct PeerSource {
    std::string addr;
    uint16_t port;
    SourceState state = SourceState::NEW;
    Timer lastActive;
    // Bitmap of available 9.5MB parts learned via OP_FILESTATUS.
    // Empty = unknown (treated optimistically as "has all").
    std::vector<bool> availableParts;
    int queuePosition = -1; // Peer's upload-queue rank (-1 = not queued)
  };
  std::vector<PeerSource> sources_;
  size_t currentSourceIndex_;

  // --- Source discovery configuration (from options) ---
  bool serverSourceEnabled_;   // PREF_ED2K_SERVER_SOURCE_ENABLED
  bool sourceExchangeEnabled_; // PREF_ED2K_SOURCE_EXCHANGE_ENABLED
  bool kadEnabled_;            // PREF_ED2K_KAD_ENABLED
  int sourceExchangeInterval_; // PREF_ED2K_SOURCE_EXCHANGE_INTERVAL (seconds)
  int listenPort_;             // PREF_ED2K_LISTEN_PORT
  int connectTimeout_;         // PREF_ED2K_CONNECTION_TIMEOUT
  bool sourceExchangeSent_;    // OP_REQUESTSOURCES sent to current peer
  Timer sourceExchangeTimer_;  // Tracks when to request sources again

  // --- Periodic source refresh ---
  Timer serverSourceRefreshTimer_;
  static const int SERVER_SOURCE_REFRESH_SECONDS = 120;
  int maxSources_; // PREF_ED2K_MAX_SOURCES_PER_FILE cap

  // --- Failed peer tracking (cooldown to avoid retrying dead peers) ---
  struct FailedPeer {
    std::string addr;
    uint16_t port;
    Timer failTime;
    bool permanent = false;
  };
  std::vector<FailedPeer> failedPeers_;
  static const int PEER_COOLDOWN_SECONDS = 300; // 5-minute cooldown

  // --- Queue wait tracking ---
  // Being queued on a peer's upload slot is normal in ED2K; wait
  // patiently but not forever.
  Timer queueWaitTimer_;
  static const int QUEUE_WAIT_SECONDS = 900; // 15 minutes max queue wait

  // --- KAD UDP source lookup ---
  std::shared_ptr<SocketCore> kadSocket_;
  std::vector<std::pair<std::string, uint16_t>> kadNodes_;
  size_t currentKadNodeIndex_;
  Timer kadRefreshTimer_;
  static const int KAD_REFRESH_SECONDS = 180;
  bool kadBootstrapSent_;
  bool kadSearchSent_;
  KadState kadState_ = KadState::BOOTSTRAP;

  // --- Part Availability Manager ---
  struct PartInfo {
    int64_t offset = 0;
    int64_t length = 0;
    bool completed = false;
    bool downloading = false;
    Timer lastRequested;
    std::vector<size_t> sources; // indices into sources_
  };
  std::vector<PartInfo> parts_;
  int64_t partSize_; // ED2K part size (9.5MB)

  // --- Download progress (truthful range tracking) ---
  // Sorted, non-overlapping [start, end) ranges written to disk.
  std::vector<Range> writtenRanges_;
  int64_t downloadOffset_;   // sequential fallback cursor
  int64_t lastMarkedLength_; // prefix length already pushed to PieceStorage

  // --- Pipelined block requests ---
  // Peers answer OP_REQUESTPARTS in order; keep a small number of blocks
  // in flight to hide latency (eMule requests up to 3 blocks per message).
  std::deque<BlockRequest> inflightBlocks_;
  static const size_t BLOCKS_PER_MESSAGE = 3; // protocol maximum
  static const size_t MAX_INFLIGHT_BLOCKS = 6; // 2 messages in flight
  bool useI64Requests_; // >4GB file: use OP_REQUESTPARTS_I64

  // --- Message-sent flags ---
  bool loginSent_;
  bool sourcesRequested_;
  bool helloSent_;
  bool emuleInfoSent_;
  bool fileInfoSent_;       // OP_REQUESTFILENAME sent
  bool setReqFileIdSent_;   // OP_SETREQFILEID sent
  bool fileStatusReceived_; // OP_FILESTATUS bitmap received (or wait expired)
  bool uploadReqSent_;
  bool endOfDownloadSent_;
  Timer fileInfoTimer_;

  // Set true when flushSendBuffer() hits a real socket error (not EAGAIN).
  bool connectionError_;

  // --- Peer connect timing ---
  Timer peerConnectTimer_;

  // --- Persistent I/O buffers ---
  std::vector<unsigned char> sendBuffer_;
  std::vector<unsigned char> recvBuffer_;

  // --- Whole-file hash verification state ---
  std::unique_ptr<Ed2kMd4> md4PartCtx_;
  std::vector<unsigned char> partHashes_; // concatenated per-part digests
  int64_t verifyOffset_;
  int64_t verifyPartStart_;
  bool verifyStarted_;

  // --- Server phase methods ---
  bool serverConnect();
  bool serverLogin();
  bool serverGetSources();
  bool serverWaitSources();

  // --- Peer phase methods ---
  bool peerConnect();
  bool peerWaitConnect();
  bool peerHandshake();
  bool peerFileInfo();
  bool peerSourceExchange();
  bool peerStartUpload();
  bool peerDownload();

  // Advance to the next peer source. If no more sources, reconnects
  // to the server for fresh sources (up to MAX_SERVER_ROUNDS).
  void tryNextPeer();

  // Reconnect to the next server in serverList_ to fetch fresh sources.
  // Returns false if all servers and rounds are exhausted (FAILURE).
  bool reconnectServer();

  // Reset all peer-phase protocol state (called when switching peers).
  void resetPeerState();

  // --- Block scheduling / disk I/O ---

  // Fill the in-flight pipeline: queue OP_REQUESTPARTS messages until
  // MAX_INFLIGHT_BLOCKS blocks are pending. Returns false if a message
  // could not be fully flushed (EAGAIN) — caller should wait writable.
  bool fillBlockPipeline();

  // Pick the next block [start, end) to request from the current peer.
  // Uses the peer's part bitmap (rarest-first across parts) and skips
  // already-written ranges. Returns false if nothing left to request
  // from this peer right now.
  bool pickNextBlock(int64_t& start, int64_t& end);

  // Lowest offset in [from, limit) that is neither written nor in flight.
  int64_t nextFreeOffset(int64_t from, int64_t limit) const;

  // Handle one OP_SENDINGPART / OP_SENDINGPART_I64 payload.
  bool handleSendingPart(const std::vector<unsigned char>& payload,
                         bool is64);

  // Write received data block to disk at the given offset and record the
  // written range. Duplicate/already-covered data is skipped.
  bool writeBlockToDisk(int64_t offset, const unsigned char* data,
                        size_t len);

  // Record a written range; advance the truthful prefix in PieceStorage.
  void recordWrittenRange(int64_t start, int64_t end);

  // Length of the contiguous written prefix starting at offset 0.
  int64_t prefixLength() const;

  // True if [start, end) is fully covered by writtenRanges_.
  bool isRangeCovered(int64_t start, int64_t end) const;

  // True if the whole file has been written.
  bool downloadComplete() const;

  // --- Whole-file hash verification (VERIFY_HASH state) ---
  // Incremental: reads VERIFY_CHUNK bytes per tick to avoid stalling
  // the event loop on multi-GB files.
  bool verifyHash();
  static const int64_t VERIFY_CHUNK = 8 * 1024 * 1024; // 8MB per tick

  // --- Source management helpers ---
  void markPeerFailed(const std::string& addr, uint16_t port,
                      bool permanent = false);
  bool isPeerInCooldown(const std::string& addr, uint16_t port);
  // Register a newly discovered source. Returns false when the source is
  // a duplicate, invalid, in cooldown, or the pool is full.
  bool addSource(const std::string& addr, uint16_t port);
  int countActiveSources();
  int getDynamicExchangeInterval();
  void sendSourceExchangeRequest();
  size_t parseSourcesAnswer(const std::vector<unsigned char>& payload);
  void checkServerSourceRefresh();

  // --- KAD (Kademlia DHT) source lookup via UDP ---
  void initKad();
  void kadStateMachine();
  void kadBootstrap();
  void kadFindSource();
  bool kadProcessResponse();

  // --- Part Availability Manager ---
  void initParts();
  void updatePartCompletion();
  void updatePartAvailability(size_t sourceIndex,
                              const std::vector<bool>& partBitmap);
  int findBestPartToDownload(size_t sourceIndex);
  size_t partIndexForOffset(int64_t offset);

  // --- Low-level protocol helpers ---
  // Queue one framed ED2K message. protocol: 0xE3 (eDonkey) or 0xC5 (eMule).
  void queueMessage(unsigned char msgType, const unsigned char* payload,
                    size_t payloadLen, unsigned char protocol = 0xE3);
  bool flushSendBuffer();
  // Receive one framed message. Sets msgProtocol to the frame's protocol
  // byte (0xE3/0xC5). Compressed frames (0xD4) are discarded and the
  // function returns false.
  bool tryReceiveMessage(unsigned char& msgType,
                         std::vector<unsigned char>& payload,
                         unsigned char& msgProtocol);
};

} // namespace aria2

#endif // D_ED2K_DOWNLOAD_COMMAND_H
