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
    
    // Set up the file entry with the ED2K file information
    getFileEntry()->setPath(fileInfo.filename);
    getFileEntry()->setLength(fileInfo.filesize);

    // The engine skips PieceStorage initialization when getTotalLength()==0
    // (which is the case for ED2K links before parsing). Now that we know
    // the file size, mark it as known and initialize PieceStorage so that
    // Ed2kDownloadCommand can write to disk and report progress.
    auto dc = getRequestGroup()->getDownloadContext();
    if (dc) {
      dc->markTotalLengthIsKnown();
    }
    getRequestGroup()->initPieceStorage();
    try {
      auto ps = getRequestGroup()->getPieceStorage();
      if (ps && ps->getDiskAdaptor()) {
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
      Ed2kHelper::getDefaultServers(servers);
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