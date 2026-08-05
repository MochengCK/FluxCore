/* <!-- copyright */
/*
 * aria2 - The high speed download utility
 *
 * Copyright (C) 2026 The XferCore Authors
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
#include "UPnPContext.h"

#include <algorithm>
#include <cstring>
#include <string>

#include "SocketCore.h"
#include "LogFactory.h"
#include "Logger.h"
#include "fmt.h"
#include "util.h"
#include "RecoverableException.h"
#include "wallclock.h"

namespace aria2 {

namespace {

// SSDP multicast address / port (UPnP-IGD v1).
constexpr char SSDP_ADDR[] = "239.255.255.250";
constexpr uint16_t SSDP_PORT = 1900;

// Short timeouts so a broken/unresponsive router can never stall the
// engine for long. Discovery is the slowest phase.
constexpr time_t SOCKET_WAIT_SECONDS = 2;
constexpr int SSDP_WAIT_MS = 1500;

constexpr char IGD_SERVICE_TYPE[] =
    "urn:schemas-upnp-org:service:WANIPConnection:1";
constexpr char IGD_SERVICE_TYPE_PPP[] =
    "urn:schemas-upnp-org:service:WANPPPConnection:1";

// Split "http://host[:port]/path" into parts. Returns false for
// non-http or malformed URLs.
bool splitHttpUrl(const std::string& url, std::string& host, uint16_t& port,
                  std::string& path)
{
  host.clear();
  path.clear();
  port = 80;
  if (!util::startsWith(url, "http://")) {
    return false;
  }
  std::string rest = url.substr(7);
  size_t slash = rest.find('/');
  std::string authority = (slash == std::string::npos) ? rest
                                                       : rest.substr(0, slash);
  path = (slash == std::string::npos) ? "/" : rest.substr(slash);
  if (authority.empty()) {
    return false;
  }
  size_t colon = authority.rfind(':');
  if (colon != std::string::npos) {
    try {
      long p = std::stol(authority.substr(colon + 1));
      if (p <= 0 || p > 65535) {
        return false;
      }
      port = static_cast<uint16_t>(p);
    }
    catch (std::exception&) {
      return false;
    }
    host = authority.substr(0, colon);
  }
  else {
    host = authority;
  }
  return !host.empty();
}

// Unescape the few XML entities that can appear in control URLs.
void xmlUnescape(std::string& s)
{
  std::string out;
  out.reserve(s.size());
  for (size_t i = 0; i < s.size();) {
    if (s.compare(i, 5, "&amp;") == 0) {
      out += '&';
      i += 5;
    }
    else if (s.compare(i, 4, "&lt;") == 0) {
      out += '<';
      i += 4;
    }
    else if (s.compare(i, 4, "&gt;") == 0) {
      out += '>';
      i += 4;
    }
    else if (s.compare(i, 6, "&quot;") == 0) {
      out += '"';
      i += 6;
    }
    else if (s.compare(i, 5, "&#39;") == 0) {
      out += '\'';
      i += 5;
    }
    else {
      out += s[i];
      ++i;
    }
  }
  s = std::move(out);
}

// Extract the text content of the first <tag>...</tag> at or after pos.
bool extractTag(const std::string& xml, const std::string& tag, size_t pos,
                std::string& out)
{
  std::string open = "<" + tag + ">";
  std::string close = "</" + tag + ">";
  size_t begin = xml.find(open, pos);
  if (begin == std::string::npos) {
    return false;
  }
  begin += open.size();
  size_t end = xml.find(close, begin);
  if (end == std::string::npos) {
    return false;
  }
  out = xml.substr(begin, end - begin);
  out = util::strip(out);
  xmlUnescape(out);
  return true;
}

// Read a full HTTP response (headers + body per Content-Length) from a
// connected non-blocking socket. Returns the raw response; empty string
// on failure/timeout. Blocks at most maxWaitSeconds.
std::string readHttpResponse(const std::shared_ptr<SocketCore>& sock,
                             time_t maxWaitSeconds)
{
  std::string resp;
  char buf[4096];
  size_t headerEnd = std::string::npos;
  size_t contentLength = 0;
  constexpr size_t MAX_RESPONSE = 64 * 1024;

  while (resp.size() < MAX_RESPONSE) {
    if (sock->isReadable(maxWaitSeconds)) {
      size_t len = sizeof(buf);
      try {
        sock->readData(buf, len);
      }
      catch (RecoverableException&) {
        return "";
      }
      if (len > 0) {
        resp.append(buf, len);
      }
      else if (!sock->wantRead()) {
        // EOF
        break;
      }
      else {
        continue;
      }
    }
    else {
      // Timed out — return what we have so far.
      break;
    }

    if (headerEnd == std::string::npos) {
      headerEnd = resp.find("\r\n\r\n");
      if (headerEnd != std::string::npos) {
        // Parse Content-Length from the header block.
        std::string headers = resp.substr(0, headerEnd);
        size_t pos = util::toLower(headers).find("content-length:");
        if (pos != std::string::npos && pos + 15 <= headers.size()) {
          size_t eol = headers.find("\r\n", pos);
          std::string val = headers.substr(
              pos + 15, (eol == std::string::npos ? headers.size() : eol) -
                            (pos + 15));
          val = util::strip(val);
          try {
            contentLength = static_cast<size_t>(std::stoull(val));
          }
          catch (std::exception&) {
            contentLength = 0;
          }
        }
        headerEnd += 4; // skip blank line
      }
    }
    // Some routers omit Content-Length; in that case keep reading until
    // EOF/timeout instead of returning an incomplete body.
    if (contentLength > 0 && headerEnd != std::string::npos &&
        resp.size() >= headerEnd + contentLength) {
      break;
    }
  }
  return resp;
}

// Write all bytes to a connected non-blocking socket, waiting for
// writability between chunks. Returns false on error/timeout.
bool writeAll(const std::shared_ptr<SocketCore>& sock, const std::string& data)
{
  size_t off = 0;
  while (off < data.size()) {
    if (!sock->isWritable(SOCKET_WAIT_SECONDS)) {
      return false;
    }
    try {
      ssize_t n = sock->writeData(data.data() + off, data.size() - off);
      if (n <= 0) {
        if (sock->wantWrite()) {
          continue;
        }
        return false;
      }
      off += static_cast<size_t>(n);
    }
    catch (RecoverableException&) {
      return false;
    }
  }
  return true;
}

} // namespace

bool UPnPContext::attemptedAny_ = false;

UPnPContext::UPnPContext() = default;

UPnPContext& getUPnPContext()
{
  static UPnPContext ctx;
  return ctx;
}

bool UPnPContext::alreadyAttempted() { return attemptedAny_; }

bool UPnPContext::addPortMapping(uint16_t port)
{
  // Only one attempt per process: the SSDP wait would otherwise stall
  // every BT download start.
  if (attemptedAny_) {
    return mapped_;
  }
  attemptedAny_ = true;
  attempted_ = true;

  if (port == 0) {
    A2_LOG_WARN("UPnP: no valid port to map, skipping NAT traversal");
    return false;
  }

  std::string location;
  if (!ssdpDiscover(location)) {
    A2_LOG_INFO(
        "UPnP: no IGD found via SSDP (firewalled NAT traversal not "
        "available; download speed may be affected by incoming-connection "
        "restrictions)");
    return false;
  }
  A2_LOG_INFO(fmt("UPnP: IGD discovered at %s", location.c_str()));

  if (!fetchControlUrl(location)) {
    A2_LOG_WARN(fmt("UPnP: failed to locate WANIP/WANPPP control service "
                    "from %s",
                    location.c_str()));
    return false;
  }

  // The SOAP body needs our LAN IP as seen by the router: the local
  // address of the TCP connection to the gateway.
  std::string host, path;
  uint16_t portNum;
  if (!splitHttpUrl(controlUrl_, host, portNum, path)) {
    A2_LOG_WARN(fmt("UPnP: invalid control URL %s", controlUrl_.c_str()));
    return false;
  }

  auto sock = std::make_shared<SocketCore>();
  try {
    sock->establishConnection(host, portNum);
  }
  catch (RecoverableException& e) {
    A2_LOG_WARN(fmt("UPnP: cannot connect to IGD %s: %s", host.c_str(),
                    e.what()));
    return false;
  }
  if (!sock->isWritable(SOCKET_WAIT_SECONDS)) {
    A2_LOG_WARN(fmt("UPnP: connect to IGD %s timed out", host.c_str()));
    return false;
  }
  std::string internalIp;
  try {
    internalIp = sock->getAddrInfo().addr;
  }
  catch (RecoverableException&) {
    internalIp = "127.0.0.1";
  }

  std::string body =
      "<?xml version=\"1.0\"?>"
      "<s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" "
      "s:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\">"
      "<s:Body>"
      "<u:AddPortMapping xmlns:u=\"" +
      serviceType_ +
      "\">"
      "<NewRemoteHost></NewRemoteHost>"
      "<NewExternalPort>" +
      util::uitos(port) +
      "</NewExternalPort>"
      "<NewProtocol>TCP</NewProtocol>"
      "<NewInternalPort>" +
      util::uitos(port) +
      "</NewInternalPort>"
      "<NewInternalClient>" +
      internalIp +
      "</NewInternalClient>"
      "<NewEnabled>1</NewEnabled>"
      "<NewPortMappingDescription>aria2</NewPortMappingDescription>"
      "<NewLeaseDuration>0</NewLeaseDuration>"
      "</u:AddPortMapping>"
      "</s:Body>"
      "</s:Envelope>";

  if (!soapAction("AddPortMapping", body, host, portNum, path)) {
    A2_LOG_WARN(fmt("UPnP: AddPortMapping for TCP port %u failed",
                    static_cast<unsigned>(port)));
    return false;
  }

  mapped_ = true;
  mappedPort_ = port;
  A2_LOG_INFO(fmt("UPnP: TCP port %u mapped on IGD (NAT traversal active)",
                  static_cast<unsigned>(port)));
  return true;
}

void UPnPContext::removePortMapping()
{
  if (!mapped_ || mappedPort_ == 0 || controlUrl_.empty()) {
    return;
  }
  std::string host, path;
  uint16_t portNum;
  if (!splitHttpUrl(controlUrl_, host, portNum, path)) {
    return;
  }
  auto sock = std::make_shared<SocketCore>();
  try {
    sock->establishConnection(host, portNum);
  }
  catch (RecoverableException&) {
    return;
  }
  if (!sock->isWritable(SOCKET_WAIT_SECONDS)) {
    return;
  }
  std::string body =
      "<?xml version=\"1.0\"?>"
      "<s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" "
      "s:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\">"
      "<s:Body>"
      "<u:DeletePortMapping xmlns:u=\"" +
      serviceType_ +
      "\">"
      "<NewRemoteHost></NewRemoteHost>"
      "<NewExternalPort>" +
      util::uitos(mappedPort_) +
      "</NewExternalPort>"
      "<NewProtocol>TCP</NewProtocol>"
      "</u:DeletePortMapping>"
      "</s:Body>"
      "</s:Envelope>";
  (void)soapAction("DeletePortMapping", body, host, portNum, path);
  mapped_ = false;
  A2_LOG_INFO("UPnP: port mapping removed on engine shutdown");
}

bool UPnPContext::ssdpDiscover(std::string& location)
{
  std::shared_ptr<SocketCore> udp;
  try {
    udp = std::make_shared<SocketCore>(SOCK_DGRAM);
    udp->bindWithFamily(0, AF_INET);
    udp->setMulticastTtl(2);
  }
  catch (RecoverableException& e) {
    A2_LOG_DEBUG(fmt("UPnP: SSDP socket init failed: %s", e.what()));
    return false;
  }

  std::string search =
      "M-SEARCH * HTTP/1.1\r\n"
      "HOST: 239.255.255.250:1900\r\n"
      "MAN: \"ssdp:discover\"\r\n"
      "MX: 1\r\n"
      "ST: urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\n"
      "\r\n";
  try {
    udp->writeData(search.data(), search.size(), SSDP_ADDR, SSDP_PORT);
  }
  catch (RecoverableException& e) {
    A2_LOG_DEBUG(fmt("UPnP: SSDP M-SEARCH send failed: %s", e.what()));
    return false;
  }

  // Collect unicast responses until the deadline. First IGD wins.
  auto deadline = global::wallclock();
  while (true) {
    auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
        deadline.difference());
    if (elapsed.count() >= SSDP_WAIT_MS) {
      break;
    }
    time_t wait = std::max<long>(
        0, (SSDP_WAIT_MS - static_cast<long>(elapsed.count()) + 999) / 1000);
    if (!udp->isReadable(wait)) {
      break;
    }
    char buf[2048];
    Endpoint sender;
    ssize_t n = 0;
    try {
      n = udp->readDataFrom(buf, sizeof(buf), sender);
    }
    catch (RecoverableException&) {
      continue;
    }
    if (n <= 0) {
      continue;
    }
    std::string packet(buf, static_cast<size_t>(n));
    if (packet.find("HTTP/1.1 200 OK") == std::string::npos &&
        packet.find("HTTP/1.0 200 OK") == std::string::npos) {
      continue;
    }
    size_t pos = util::toLower(packet).find("location:");
    if (pos == std::string::npos) {
      continue;
    }
    size_t eol = packet.find("\r\n", pos);
    std::string loc = packet.substr(
        pos + 9, (eol == std::string::npos ? packet.size() : eol) - (pos + 9));
    loc = util::strip(loc);
    if (util::startsWith(loc, "http://")) {
      location = loc;
      return true;
    }
  }
  return false;
}

bool UPnPContext::fetchControlUrl(const std::string& location)
{
  std::string host, path;
  uint16_t portNum;
  if (!splitHttpUrl(location, host, portNum, path)) {
    A2_LOG_WARN(fmt("UPnP: cannot parse device description URL %s",
                    location.c_str()));
    return false;
  }
  auto sock = std::make_shared<SocketCore>();
  try {
    sock->establishConnection(host, portNum);
  }
  catch (RecoverableException& e) {
    A2_LOG_DEBUG(fmt("UPnP: connect to %s failed: %s", host.c_str(),
                     e.what()));
    return false;
  }
  if (!sock->isWritable(SOCKET_WAIT_SECONDS)) {
    return false;
  }
  std::string req = "GET " + path + " HTTP/1.1\r\nHost: " + host + ":" +
                    util::uitos(portNum) + "\r\n\r\n";
  if (!writeAll(sock, req)) {
    return false;
  }
  std::string xml = readHttpResponse(sock, SOCKET_WAIT_SECONDS);
  if (xml.empty()) {
    A2_LOG_DEBUG(fmt("UPnP: no device description from %s", location.c_str()));
    return false;
  }

  // Find the WAN IP/PPP connection service, then take the controlURL
  // that follows it inside the same service block.
  size_t pos = 0;
  while (true) {
    std::string svc;
    if (!extractTag(xml, "serviceType", pos, svc)) {
      break;
    }
    pos = xml.find("</serviceType>", pos);
    if (pos == std::string::npos) {
      break;
    }
    pos += std::string("</serviceType>").size();

    if (svc == IGD_SERVICE_TYPE || svc == IGD_SERVICE_TYPE_PPP) {
      std::string ctl;
      if (extractTag(xml, "controlURL", pos, ctl)) {
        if (ctl.empty()) {
          ctl = "/";
        }
        else if (ctl[0] != '/') {
          // Relative to the device description URL's directory.
          size_t lastSlash = location.rfind('/');
          std::string base = (lastSlash == std::string::npos)
                                 ? location
                                 : location.substr(0, lastSlash);
          ctl = base + "/" + ctl;
        }
        else {
          ctl = "http://" + host + ":" + util::uitos(portNum) + ctl;
        }
        controlUrl_ = ctl;
        serviceType_ = svc;
        return true;
      }
    }
  }
  return false;
}

bool UPnPContext::soapAction(const std::string& actionName,
                             const std::string& body, const std::string& host,
                             uint16_t port, const std::string& path)
{
  auto sock = std::make_shared<SocketCore>();
  try {
    sock->establishConnection(host, port);
  }
  catch (RecoverableException& e) {
    A2_LOG_DEBUG(fmt("UPnP: connect to IGD %s failed: %s", host.c_str(),
                     e.what()));
    return false;
  }
  if (!sock->isWritable(SOCKET_WAIT_SECONDS)) {
    return false;
  }
  std::string req = "POST " + path + " HTTP/1.1\r\nHost: " + host + ":" +
                    util::uitos(port) +
                    "\r\nContent-Type: text/xml; charset=\"utf-8\"\r\n"
                    "SOAPAction: \"" +
                    serviceType_ + "#" + actionName +
                    "\"\r\nContent-Length: " + util::uitos(body.size()) +
                    "\r\n\r\n" + body;
  if (!writeAll(sock, req)) {
    return false;
  }
  std::string resp = readHttpResponse(sock, SOCKET_WAIT_SECONDS);
  if (resp.empty()) {
    A2_LOG_WARN(fmt("UPnP: no response to %s from IGD", actionName.c_str()));
    return false;
  }
  if (resp.find(actionName + "Response") == std::string::npos) {
    // Failure — surface the UPnP error code when present.
    std::string errCode;
    if (extractTag(resp, "errorCode", 0, errCode)) {
      A2_LOG_WARN(fmt("UPnP: %s rejected by IGD with UPnP error %s",
                      actionName.c_str(), errCode.c_str()));
    }
    else {
      A2_LOG_WARN(fmt("UPnP: %s rejected by IGD (unexpected response)",
                      actionName.c_str()));
    }
    return false;
  }
  return true;
}

} // namespace aria2
