// Cross-platform socket abstraction (Winsock on Windows, BSD sockets elsewhere).
#pragma once

#include <stdexcept>

#ifdef _WIN32
  #include <winsock2.h>
  #include <ws2tcpip.h>

  using socket_t = SOCKET;
  constexpr socket_t kInvalidSocket = INVALID_SOCKET;
  inline void closeSocket(socket_t s) { closesocket(s); }
  inline void setNonBlocking(socket_t s, bool enable) {
    u_long mode = enable ? 1 : 0;
    ioctlsocket(s, FIONBIO, &mode);
  }
#else
  #include <arpa/inet.h>
  #include <fcntl.h>
  #include <netdb.h>
  #include <sys/select.h>
  #include <sys/socket.h>
  #include <unistd.h>

  using socket_t = int;
  constexpr socket_t kInvalidSocket = -1;
  inline void closeSocket(socket_t s) { close(s); }
  inline void setNonBlocking(socket_t s, bool enable) {
    int flags = fcntl(s, F_GETFL, 0);
    fcntl(s, F_SETFL, enable ? (flags | O_NONBLOCK) : (flags & ~O_NONBLOCK));
  }
#endif

// RAII wrapper: initializes Winsock on Windows, does nothing elsewhere.
class NetworkSession {
 public:
  NetworkSession() {
#ifdef _WIN32
    WSADATA data;
    if (WSAStartup(MAKEWORD(2, 2), &data) != 0) {
      throw std::runtime_error("WSAStartup failed");
    }
#endif
  }
  ~NetworkSession() {
#ifdef _WIN32
    WSACleanup();
#endif
  }
  NetworkSession(const NetworkSession&) = delete;
  NetworkSession& operator=(const NetworkSession&) = delete;
};
