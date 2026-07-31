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
#include "Logger.h"
#include "LogFactory.h"
#include "message.h"
#include "prefs.h"
#include "SocketCore.h"
#include "util.h"
#include "fmt.h"
#include "FileEntry.h"
#include "RequestGroup.h"
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
  // ED2K links are of the form:
  // ed2k://|file|<filename>|<filesize>|<filehash>|h=<parthash1>,<parthash2>,...|/
  // or
  // ed2k://|file|<filename>|<filesize>|<filehash>|p=<server_ip>:<server_port>|/
  
  const std::string& uri = getRequest()->getUri();
  
  A2_LOG_INFO(fmt("CUID#%" PRId64 " - Processing ED2K link: %s",
                  getCuid(), uri.c_str()));
  
  // Parse the ED2K link using Ed2kHelper
  Ed2kFileInfo fileInfo;
  if (!Ed2kHelper::parseLink(uri, fileInfo)) {
    throw DL_ABORT_EX(
        fmt("Failed to parse ED2K link: %s", uri.c_str()));
  }
  
  A2_LOG_INFO(fmt("CUID#%" PRId64 " - ED2K file: %s, size: %" PRId64 ", hash: %s",
                  getCuid(), fileInfo.filename.c_str(),
                  fileInfo.filesize, fileInfo.filehash.c_str()));
  
  // Set up the file entry with the ED2K file information
  getFileEntry()->setPath(fileInfo.filename);
  getFileEntry()->setLength(fileInfo.filesize);
  
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
                    getCuid(), static_cast<unsigned long>(servers.size())));
  }
  
  // Try to connect to each server until we find one that responds
  bool connected = false;
  std::shared_ptr<SocketCore> serverSocket;
  std::string connectedAddr;
  uint16_t connectedPort = 0;
  
  for (const auto& server : servers) {
    A2_LOG_INFO(fmt("CUID#%" PRId64 " - Attempting to connect to ED2K server %s:%u",
                    getCuid(), server.addr.c_str(), server.port));
    
    try {
      createSocket();
      getSocket()->establishConnection(server.addr, server.port);
      getSocket()->setBlockingMode();
      
      // Send ED2K login handshake
      if (Ed2kHelper::sendLoginHandshake(getSocket(), getOption())) {
        // Send search request for the file
        if (Ed2kHelper::searchFile(getSocket(), fileInfo)) {
          serverSocket = getSocket();
          connectedAddr = server.addr;
          connectedPort = server.port;
          connected = true;
          A2_LOG_INFO(fmt("CUID#%" PRId64 " - Successfully connected to ED2K server %s:%u",
                          getCuid(), server.addr.c_str(), server.port));
          break;
        }
      }
      
      getSocket()->closeConnection();
    }
    catch (RecoverableException& ex) {
      A2_LOG_INFO_EX(fmt("CUID#%" PRId64 " - Failed to connect to ED2K server %s:%u",
                         getCuid(), server.addr.c_str(), server.port),
                     ex);
      // Try the next server
    }
  }
  
  if (!connected) {
    throw DL_ABORT_EX(
        fmt("CUID#%" PRId64 " - Failed to connect to any ED2K server",
            getCuid()));
  }
  
  // Search for sources (other clients) that have the file
  A2_LOG_INFO(fmt("CUID#%" PRId64 " - Searching for ED2K file sources...",
                  getCuid()));
  
  std::vector<Ed2kSourceEntry> sources;
  if (!Ed2kHelper::getFileSources(serverSocket, fileInfo, sources)) {
    A2_LOG_INFO(fmt("CUID#%" PRId64 " - No sources found for ED2K file, will retry later",
                    getCuid()));
  }
  
  A2_LOG_INFO(fmt("CUID#%" PRId64 " - Found %lu sources for ED2K file",
                  getCuid(), static_cast<unsigned long>(sources.size())));
  
  // Create Ed2kDownloadCommand to start downloading
  // Constructor takes 7 params: cuid, req, fileEntry, requestGroup, e, s
  auto c = make_unique<Ed2kDownloadCommand>(
      getCuid(), getRequest(), getFileEntry(), getRequestGroup(),
      getDownloadEngine(), serverSocket);
  
  c->setFileHash(fileInfo.filehash);
  c->setFileSize(fileInfo.filesize);
  c->setStatus(Command::STATUS_ONESHOT_REALTIME);
  getDownloadEngine()->setNoWait(true);
  getDownloadEngine()->addCommand(std::move(c));
  
  return true;
}

} // namespace aria2