#include "scanner.hpp"

#include <algorithm>
#include <atomic>
#include <cctype>
#include <cstring>
#include <thread>

namespace {

// Waits until the socket is readable (or writable) or the timeout expires.
bool waitForSocket(socket_t sock, bool forWrite, int timeoutMs) {
  fd_set fds;
  FD_ZERO(&fds);
  FD_SET(sock, &fds);

  timeval timeout{};
  timeout.tv_sec = timeoutMs / 1000;
  timeout.tv_usec = (timeoutMs % 1000) * 1000;

  int ready = forWrite ? select(static_cast<int>(sock) + 1, nullptr, &fds, nullptr, &timeout)
                       : select(static_cast<int>(sock) + 1, &fds, nullptr, nullptr, &timeout);
  return ready > 0;
}

// Reads whatever the service volunteers on connect (SSH, FTP and SMTP all do).
std::string grabBanner(socket_t sock, int timeoutMs) {
  if (!waitForSocket(sock, false, std::min(timeoutMs, 1000))) return "";

  char buffer[256];
  int received = static_cast<int>(recv(sock, buffer, sizeof(buffer) - 1, 0));
  if (received <= 0) return "";

  std::string banner;
  for (int i = 0; i < received && buffer[i] != '\n' && buffer[i] != '\r'; i++) {
    unsigned char c = static_cast<unsigned char>(buffer[i]);
    banner += std::isprint(c) ? static_cast<char>(c) : '.';
  }
  return banner;
}

}  // namespace

bool resolveHost(const std::string& host, sockaddr_in& address) {
  addrinfo hints{};
  hints.ai_family = AF_INET;
  hints.ai_socktype = SOCK_STREAM;

  addrinfo* result = nullptr;
  if (getaddrinfo(host.c_str(), nullptr, &hints, &result) != 0 || result == nullptr) {
    return false;
  }
  std::memcpy(&address, result->ai_addr, sizeof(sockaddr_in));
  freeaddrinfo(result);
  return true;
}

PortResult scanPort(const sockaddr_in& address, int port, int timeoutMs) {
  PortResult result;
  result.port = port;

  socket_t sock = socket(AF_INET, SOCK_STREAM, 0);
  if (sock == kInvalidSocket) return result;

  sockaddr_in target = address;
  target.sin_port = htons(static_cast<unsigned short>(port));

  // Non-blocking connect so the timeout can be enforced with select().
  setNonBlocking(sock, true);
  connect(sock, reinterpret_cast<sockaddr*>(&target), sizeof(target));

  if (waitForSocket(sock, true, timeoutMs)) {
    // select() also fires when the connection fails, so check the socket error.
    int error = 0;
    socklen_t length = sizeof(error);
    getsockopt(sock, SOL_SOCKET, SO_ERROR, reinterpret_cast<char*>(&error), &length);
    result.open = (error == 0);
  }

  if (result.open) result.banner = grabBanner(sock, timeoutMs);

  closeSocket(sock);
  return result;
}

std::vector<PortResult> scanRange(const sockaddr_in& address, int firstPort, int lastPort,
                                  int timeoutMs, int threads) {
  const int total = lastPort - firstPort + 1;
  std::vector<PortResult> results(total);
  std::atomic<int> next{0};

  auto worker = [&]() {
    for (int i = next++; i < total; i = next++) {
      results[i] = scanPort(address, firstPort + i, timeoutMs);  // each index written once
    }
  };

  std::vector<std::thread> pool;
  for (int t = 0; t < std::min(threads, total); t++) pool.emplace_back(worker);
  for (auto& thread : pool) thread.join();
  return results;
}
