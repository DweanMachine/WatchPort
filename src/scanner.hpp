// TCP connect scanning with optional banner grabbing.
#pragma once

#include <string>
#include <vector>

#include "platform.hpp"

struct PortResult {
  int port = 0;
  bool open = false;
  std::string banner;  // First line sent by the service, if any
};

// Resolves a hostname or IPv4 address. Returns false if it cannot be resolved.
bool resolveHost(const std::string& host, sockaddr_in& address);

// Checks a single TCP port and, if open, tries to read a service banner.
PortResult scanPort(const sockaddr_in& address, int port, int timeoutMs);

// Scans [firstPort, lastPort] using up to `threads` worker threads.
// Returns one result per port, in port order.
std::vector<PortResult> scanRange(const sockaddr_in& address, int firstPort, int lastPort,
                                  int timeoutMs, int threads);
