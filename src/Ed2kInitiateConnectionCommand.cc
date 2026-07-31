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
#include "Ed2kInitiateConnectionCommand.h"

#include <map>

#include "DownloadEngine.h"
#include "Option.h"
#include "Request.h"
#include "Ed2kHelper.h"
#include "Ed2kDownloadCommand.h"
#include "Segment.h"
#include "DlAbortEx.h"
#include "error_code.h"
#include "RecoverableException.h"
#include "Logger.h"
#include "LogFactory.h"
#include "message.h"
#include "prefs.h"
#include "SocketCore.h"
#include "util.h"
#include "fmt.h"
#include "FileEntry.h"
#include "RequestGroup.h"
#include "DownloadContext.h"
#include "PieceStorage.h"
#include "DiskAdaptor.h"
#include "DefaultBtProgressInfoFile.h"
#include "A2STR.h"

namespace aria2 {

Ed2kInitiateConnectionCommand::Ed2kInitiateConnectionCommand(
    cuid_t cuid, const std::shared_ptr<Request>& req,
    const std::shared_ptr<FileEntry>& fileEntry, RequestGroup* requestGroup,
    DownloadEngine* e)
    : InitiateConnectionCommand(cuid, req, fileEntry, requestGroup, e)
{
}

Ed2kInitiateConnectionCommand::~Ed2kInitiateConnectionCommand() = default;

std::unique_ptr<Command> Ed2kInitiateConnectionCommand::createNextCommand(
    const std::string& hostname, const std::string& addr, uint16_t port,
    const std::vector<std::string>& resolvedAddresses,
    const std::shared_ptr<Request>& proxyRequest)
{
  // ED2K connections use a custom execute() flow that bypasses
  // the standard InitiateConnectionCommand pipeline.
  return nullptr;
}

bool Ed2kInitiateConnectionCommand::execute()
{
  // ED2K uses a single P2P connection — the protocol handles multi-source
  // downloading internally. Force numConcurrentCommand to 1 to prevent
  // RequestGroup from spawning PREF_SPLIT (often 32) parallel
  // CreateRequestCommands, each of which would create an
  // Ed2kInitiateConnectionCommand → Ed2kDownloadCommand. Multiple
  // Ed2kDownloadCommands writing to the same PieceStorage cause
  // "Found duplicate cache entry" assertion crashes in Piece::initWrCache.
  getRequestGroup()->setNumConcurrentCommand(1);

  // If another Ed2kInitiateConnectionCommand already created an
  // Ed2kDownloadCommand for this RequestGroup, don't create another.
  // getNumConnection() counts active stream connections; this command
  // itself counts as 1, so >1 means a download command is already running.
  if (getRequestGroup()->getNumConnection() > 1) {
    A2_LOG_INFO(fmt("CUID#%" PRId64 " - ED2K: download already active,"
                    " skipping duplicate command", getCuid()));
    return true;
  }

  try {
    // ED2K links are of the form:
    // ed2k://|file|<filename>|<filesize>|<filehash>|/
    // or with optional server hint: ...|p=<server_ip>:<server_port>|/

    const std::string& uri = getRequest()->getUri();

    A2_LOG_INFO(fmt("CUID#%" PRId64 " - Processing ED2K link: %s",
                    getCuid(), uri.c_str()));

    // Parse the ED2K link using Ed2kHelper
    Ed2kFileInfo fileInfo;
    if (!Ed2kHelper::parseLink(uri, fileInfo)) {
      A2_LOG_ERROR(fmt("CUID#%" PRId64 " - Failed to parse ED2K link: %s",
                       getCuid(), uri.c_str()));
      getRequestGroup()->setLastErrorCode(error_code::UNKNOWN_ERROR,
                                          "Failed to parse ED2K link");
      return true;
    }

    A2_LOG_INFO(fmt("CUID#%" PRId64 " - ED2K file: %s, size: %" PRId64
                    ", hash: %s",
                    getCuid(), fileInfo.filename.c_str(),
                    fileInfo.filesize, fileInfo.filehash.c_str()));

    // Check if PieceStorage is already initialized. This happens when
    // the download is resumed after pause: RequestGroup::initiateDownload()
    // sees getTotalLength() > 0 (set during the first run) and calls
    // initPieceStorage() via the file-allocation path before any
    // Ed2kInitiateConnectionCommand runs. Re-calling initPieceStorage()
    // would replace the existing PieceStorage, losing disk adaptor state.
    bool pieceStorageReady = false;
    {
      auto existingPs = getRequestGroup()->getPieceStorage();
      if (existingPs && existingPs->getDiskAdaptor()) {
        pieceStorageReady = true;
      }
    }

    // Set up the file entry with the ED2K file information.
    // Apply the user-configured download directory (PREF_DIR) so the file
    // lands in the same place as normal HTTP/BT downloads.
    const std::string& dir = getOption()->get(PREF_DIR);
    getFileEntry()->setPath(util::applyDir(dir, fileInfo.filename));
    getFileEntry()->setSuffixPath(fileInfo.filename);
    getFileEntry()->setLength(fileInfo.filesize);

    if (!pieceStorageReady) {
      // First run: PieceStorage not yet initialized.
      // Set piece length before initPieceStorage — pieceLength_ defaults to 0
      // and DefaultPieceStorage/BitfieldMan divide by blockLength in
      // markPiecesDone(), causing a division-by-zero crash if left at 0.
      // Use 1MB (the aria2 default) for progress tracking granularity.
      auto dc = getRequestGroup()->getDownloadContext();
      if (dc) {
        dc->setPieceLength(1048576);
        dc->markTotalLengthIsKnown();
      }
      getRequestGroup()->initPieceStorage();
      try {
        auto ps = getRequestGroup()->getPieceStorage();
        if (ps && ps->getDiskAdaptor()) {
          // Remove any stale .aria2 control file from a previous crashed run.
          // DefaultBtProgressInfoFile::load() on a stale/corrupt file creates
          // invalid Piece objects that trigger a Piece::initWrCache assertion
          // crash. ED2K downloads always start fresh — resume is handled by
          // the session serializer (URI + options), not piece-level control.
          auto progressInfoFile = std::make_shared<DefaultBtProgressInfoFile>(
              dc, ps, getOption().get());
          if (progressInfoFile->exists()) {
            A2_LOG_INFO(fmt("CUID#%" PRId64
                            " - ED2K: removing stale control file",
                            getCuid()));
            progressInfoFile->removeFile();
          }

          ps->getDiskAdaptor()->openFile();
        }
      }
      catch (RecoverableException& e) {
        A2_LOG_ERROR_EX(fmt("CUID#%" PRId64
                            " - ED2K: failed to open disk file: %s",
                            getCuid(), e.what()),
                        e);
        getRequestGroup()->setLastErrorCode(error_code::FILE_IO_ERROR,
                                            e.what());
        return true;
      }
    }

    // Determine which ED2K servers to connect to
    std::vector<Ed2kServerEntry> servers;
    
    if (!fileInfo.serverAddr.empty() && fileInfo.serverPort > 0) {
      // Use the server specified in the link
      Ed2kServerEntry server;
      server.addr = fileInfo.serverAddr;
      server.port = fileInfo.serverPort;
      servers.push_back(server);
      A2_LOG_INFO(fmt("CUID#%" PRId64 " - Using ED2K server from link: %s:%u",
                      getCuid(), server.addr.c_str(), server.port));
    }
    
    // If no server was specified in the link, use default servers
    if (servers.empty()) {
      Ed2kHelper::getDefaultServers(servers, getOption().get());
      A2_LOG_INFO(fmt("CUID#%" PRId64 " - Using %lu default ED2K servers",
                      getCuid(),
                      static_cast<unsigned long>(servers.size())));
    }
    
    // Try to connect to each server until we find one that responds
    // Only establish TCP connection — no ED2K protocol exchange here.
    // The Ed2kDownloadCommand will handle the full ED2K protocol (handshake,
    // file search, etc.) from scratch on the connected socket.
    bool connected = false;
    std::shared_ptr<SocketCore> serverSocket;
    std::string connectedAddr;
    uint16_t connectedPort = 0;
    
    for (const auto& server : servers) {
      A2_LOG_INFO(fmt("CUID#%" PRId64
                      " - Attempting to connect to ED2K server %s:%u",
                      getCuid(), server.addr.c_str(), server.port));
      
      try {
        createSocket();
        getSocket()->establishConnection(server.addr, server.port);
        
        serverSocket = getSocket();
        connectedAddr = server.addr;
        connectedPort = server.port;
        connected = true;
        A2_LOG_INFO(fmt("CUID#%" PRId64
                        " - TCP connected to ED2K server %s:%u",
                        getCuid(), server.addr.c_str(), server.port));
        break;
      }
      catch (RecoverableException& ex) {
        A2_LOG_INFO_EX(
            fmt("CUID#%" PRId64 " - Failed to connect to ED2K server %s:%u",
                getCuid(), server.addr.c_str(), server.port),
            ex);
        // Try the next server
      }
    }
    
    if (!connected) {
      A2_LOG_ERROR(
          fmt("CUID#%" PRId64 " - Failed to connect to any ED2K server",
              getCuid()));
      getRequestGroup()->setLastErrorCode(error_code::UNKNOWN_ERROR,
                                          "Failed to connect to any ED2K server");
      return true;
    }
    
    // Create Ed2kDownloadCommand to handle the full ED2K protocol
    // (handshake, file search, data download) on the connected socket.
    auto c = make_unique<Ed2kDownloadCommand>(
        getCuid(), getRequest(), getFileEntry(), getRequestGroup(),
        getDownloadEngine(), serverSocket);

    c->setFileHash(fileInfo.filehash);
    c->setFileSize(fileInfo.filesize);
    c->setServerAddr(connectedAddr, connectedPort);

    // Pass the full server list so Ed2kDownloadCommand can rotate to
    // other servers if the initial one fails (non-blocking connect may
    // report EINPROGRESS here but fail later with SO_ERROR).
    {
      std::vector<std::pair<std::string, uint16_t>> serverList;
      for (const auto& s : servers) {
        serverList.push_back({s.addr, s.port});
      }
      c->setServerList(serverList);
    }

    c->setStatus(Command::STATUS_ONESHOT_REALTIME);
    getDownloadEngine()->setNoWait(true);
    getDownloadEngine()->addCommand(std::move(c));
    
    return true;
  }
  catch (RecoverableException& e) {
    A2_LOG_ERROR_EX(fmt("CUID#%" PRId64 " - ED2K download error: %s",
                        getCuid(), getRequest()->getUri().c_str()),
                    e);
    getRequestGroup()->setLastErrorCode(error_code::UNKNOWN_ERROR, e.what());
    return true;
  }
  catch (std::exception& e) {
    A2_LOG_ERROR(fmt("CUID#%" PRId64
                     " - ED2K unexpected error: %s",
                     getCuid(), e.what()));
    getRequestGroup()->setLastErrorCode(error_code::UNKNOWN_ERROR, e.what());
    return true;
  }
}

} // namespace aria2