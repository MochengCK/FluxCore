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
#include "AsyncNameResolver.h"

#include <cstring>

#ifdef _WIN32
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#endif

#include "A2STR.h"
#include "LogFactory.h"
#include "SocketCore.h"
#include "util.h"
#include "EventPoll.h"

namespace aria2 {

void callback(void* arg, int status, int timeouts, ares_addrinfo* result)
{
  AsyncNameResolver* resolverPtr = reinterpret_cast<AsyncNameResolver*>(arg);
  if (status != ARES_SUCCESS) {
    resolverPtr->error_ = ares_strerror(status);
    resolverPtr->status_ = AsyncNameResolver::STATUS_ERROR;
    A2_LOG_DEBUG(fmt("DNS resolution failed for %s: %s (timeouts: %d)", 
                     resolverPtr->hostname_.c_str(),
                     ares_strerror(status), timeouts));
    return;
  }
  
  if (!result) {
    resolverPtr->error_ = "no result returned from DNS query";
    resolverPtr->status_ = AsyncNameResolver::STATUS_ERROR;
    A2_LOG_DEBUG(fmt("DNS resolution failed for %s: no result returned", 
                     resolverPtr->hostname_.c_str()));
    return;
  }
  
  for (auto ap = result->nodes; ap; ap = ap->ai_next) {
    char addrstring[NI_MAXHOST];
    auto rv = getnameinfo(ap->ai_addr, ap->ai_addrlen, addrstring,
                          sizeof(addrstring), nullptr, 0, NI_NUMERICHOST);
    if (rv == 0) {
      // Check for fake-ip addresses (commonly used by proxy software)
      // 198.18.0.0/15 is a common fake-ip range used by Clash and similar proxies
      bool isFakeIP = false;
      if (ap->ai_family == AF_INET) {
        struct sockaddr_in* addr_in = (struct sockaddr_in*)ap->ai_addr;
        uint32_t ip = ntohl(addr_in->sin_addr.s_addr);
        // Check if IP is in 198.18.0.0/15 range (198.18.0.0 - 198.19.255.255)
        if ((ip >= 0xC6120000 && ip <= 0xC613FFFF)) {
          isFakeIP = true;
          A2_LOG_WARN(fmt("DNS resolved %s to fake-ip address %s. "
                          "This is likely caused by proxy software (Clash/V2Ray) using fake-ip mode. "
                          "Please configure your proxy to use real-ip mode or exclude this domain.",
                          resolverPtr->hostname_.c_str(), addrstring));
        }
      }
      
      if (!isFakeIP) {
        resolverPtr->resolvedAddresses_.push_back(addrstring);
        A2_LOG_DEBUG(fmt("DNS resolved %s to %s", 
                         resolverPtr->hostname_.c_str(), addrstring));
      }
    }
  }
  ares_freeaddrinfo(result);
  if (resolverPtr->resolvedAddresses_.empty()) {
    resolverPtr->error_ = "DNS returned fake-ip or no valid addresses. "
                          "If using proxy software (Clash/V2Ray), please switch from fake-ip to real-ip mode.";
    resolverPtr->status_ = AsyncNameResolver::STATUS_ERROR;
    A2_LOG_ERROR(fmt("DNS resolution failed for %s: %s", 
                     resolverPtr->hostname_.c_str(), 
                     resolverPtr->error_.c_str()));
  }
  else {
    resolverPtr->status_ = AsyncNameResolver::STATUS_SUCCESS;
    A2_LOG_DEBUG(fmt("DNS resolution successful for %s: %zu address(es) found", 
                     resolverPtr->hostname_.c_str(), 
                     resolverPtr->resolvedAddresses_.size()));
  }
}

namespace {
void sock_state_cb(void* arg, ares_socket_t fd, int read, int write)
{
  auto resolver = static_cast<AsyncNameResolver*>(arg);

  resolver->handle_sock_state(fd, read, write);
}
} // namespace

void AsyncNameResolver::handle_sock_state(ares_socket_t fd, int read, int write)
{
  int events = 0;

  if (read) {
    events |= EventPoll::EVENT_READ;
  }

  if (write) {
    events |= EventPoll::EVENT_WRITE;
  }

  auto it = std::find_if(
      std::begin(socks_), std::end(socks_),
      [fd](const AsyncNameResolverSocketEntry& ent) { return ent.fd == fd; });
  if (it == std::end(socks_)) {
    if (!events) {
      return;
    }

    socks_.emplace_back(AsyncNameResolverSocketEntry{fd, events});

    return;
  }

  if (!events) {
    socks_.erase(it);
    return;
  }

  (*it).events = events;
}

AsyncNameResolver::AsyncNameResolver(int family, const std::string& servers)
    : status_(STATUS_READY), family_(family), channel_(nullptr)
{
  // c-ares 1.34.6+ uses ares_channel_t* instead of ares_channel
  // Use ares_init_options() to set socket state callback and other options
  ares_options opts{};
  opts.sock_state_cb = sock_state_cb;
  opts.sock_state_cb_data = this;
  
  // Configure options to use system DNS and improve reliability
  int optmask = ARES_OPT_SOCK_STATE_CB;
  
  // Set timeout and retry parameters for better reliability
  opts.timeout = 5000;  // 5 seconds timeout per query
  opts.tries = 3;       // Retry 3 times
  optmask |= ARES_OPT_TIMEOUTMS | ARES_OPT_TRIES;
  
  // Enable EDNS for better DNS support
  opts.ednspsz = 1232;  // Standard EDNS buffer size
  optmask |= ARES_OPT_EDNSPSZ;
  
  // On Windows, explicitly request to use system DNS configuration
  // This helps c-ares properly read Windows DNS settings
#ifdef _WIN32
  opts.flags = ARES_FLAG_USEVC;  // Use TCP for DNS queries on Windows for better reliability
  optmask |= ARES_OPT_FLAGS;
#endif
  
  int status = ares_init_options(&channel_, &opts, optmask);
  if (status != ARES_SUCCESS) {
    A2_LOG_ERROR(fmt("ares_init_options failed: %s", ares_strerror(status)));
    return;
  }

  // Set DNS servers if provided
  if (!servers.empty()) {
    status = ares_set_servers_csv(channel_, servers.c_str());
    if (status != ARES_SUCCESS) {
      A2_LOG_ERROR(fmt("ares_set_servers_csv failed: %s", ares_strerror(status)));
    }
    else {
      A2_LOG_INFO(fmt("Using custom DNS servers: %s", servers.c_str()));
    }
  }
  else {
    // Log that we're using system DNS
    A2_LOG_INFO("Using system DNS configuration");
    
    // Verify that c-ares can access system DNS servers
    // This is especially important on Windows where DNS configuration
    // might not be properly detected
    ares_addr_port_node* servers_list = nullptr;
    status = ares_get_servers_ports(channel_, &servers_list);
    if (status == ARES_SUCCESS && servers_list) {
      A2_LOG_DEBUG("System DNS servers detected:");
      for (ares_addr_port_node* node = servers_list; node; node = node->next) {
        char addr_buf[46];
        const char* addr_str = nullptr;
        if (node->family == AF_INET) {
          addr_str = inet_ntop(AF_INET, &node->addr.addr4, addr_buf, sizeof(addr_buf));
        } else if (node->family == AF_INET6) {
          addr_str = inet_ntop(AF_INET6, &node->addr.addr6, addr_buf, sizeof(addr_buf));
        }
        if (addr_str) {
          A2_LOG_DEBUG(fmt("  - %s:%d", addr_str, node->udp_port));
        }
      }
      ares_free_data(servers_list);
    }
    else {
      A2_LOG_WARN(fmt("Failed to get system DNS servers: %s. DNS resolution may fail.", 
                      ares_strerror(status)));
    }
  }
}

AsyncNameResolver::~AsyncNameResolver() 
{ 
  if (channel_) {
    ares_destroy(channel_);
    channel_ = nullptr;
  }
}

void AsyncNameResolver::resolve(const std::string& name)
{
  hostname_ = name;
  status_ = STATUS_QUERYING;

  ares_addrinfo_hints hints{};
  hints.ai_family = family_;
  hints.ai_socktype = SOCK_STREAM;  // Specify socket type for better compatibility
  hints.ai_flags = ARES_AI_CANONNAME;  // Request canonical name

  A2_LOG_DEBUG(fmt("Starting DNS resolution for %s (family: %d)", 
                   name.c_str(), family_));
  
  ares_getaddrinfo(channel_, name.c_str(), nullptr, &hints, callback, this);
}

ares_socket_t AsyncNameResolver::getFds(fd_set* rfdsPtr, fd_set* wfdsPtr) const
{
  ares_socket_t nfds = 0;

  for (const auto& ent : socks_) {
    if (ent.events & EventPoll::EVENT_READ) {
      FD_SET(ent.fd, rfdsPtr);
      nfds = std::max(nfds, ent.fd + 1);
    }

    if (ent.events & EventPoll::EVENT_WRITE) {
      FD_SET(ent.fd, wfdsPtr);
      nfds = std::max(nfds, ent.fd + 1);
    }
  }

  return nfds;
}

void AsyncNameResolver::process(fd_set* rfdsPtr, fd_set* wfdsPtr)
{
  for (const auto& ent : socks_) {
    ares_socket_t readfd = ARES_SOCKET_BAD;
    ares_socket_t writefd = ARES_SOCKET_BAD;

    if (FD_ISSET(ent.fd, rfdsPtr) && (ent.events & EventPoll::EVENT_READ)) {
      readfd = ent.fd;
    }

    if (FD_ISSET(ent.fd, wfdsPtr) && (ent.events & EventPoll::EVENT_WRITE)) {
      writefd = ent.fd;
    }

    if (readfd != ARES_SOCKET_BAD || writefd != ARES_SOCKET_BAD) {
      process(readfd, writefd);
    }
  }
}

#ifdef HAVE_LIBCARES

const std::vector<AsyncNameResolverSocketEntry>&
AsyncNameResolver::getsock() const
{
  return socks_;
}

void AsyncNameResolver::process(ares_socket_t readfd, ares_socket_t writefd)
{
  ares_process_fd(channel_, readfd, writefd);
}

#endif // HAVE_LIBCARES

bool AsyncNameResolver::operator==(const AsyncNameResolver& resolver) const
{
  return this == &resolver;
}

} // namespace aria2
