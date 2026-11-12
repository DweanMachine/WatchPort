#include <iostream> //Console I/O
#include <string>   //String handling
#include <vector>   //Storing port lists/results
#include <thread>   //Multi-threaded scanning
#include <mutex>    //Thread-safe output
#include <chrono>   //Timeouts and timing
#include <future>   //Async tasks
#include <fstream>  //
#include <filesystem>

//Network-specific (cross-platform)
#ifdef _WIN32
  #include <winsock2.h>
  #include <ws2tcpip.h>
  #pragma comment(lib, "ws2_32.lib")
  //Socket types & functions [Windows]
  typedef SOCKET  socket_t;
  #define INVALID_SOCK  INVALID_SOCKET
  #define CLOSE_SOCK(s) closesocket(s)
  WSADATA wsaData;
#else
  #include <sys/socket.h>   //Socket creation
  #include <arpa/inet.h>    //IP address conversion
  #include <netdb.h>        //DNS resolution
  #include <unistd.h>       //close()
  #include <fcntl.h>        //Non-blocking sockets (fcntl)
  #include <errno.h>        //Error codes
  //Socket types & functions [Unix-like]
  typedef int     socket_t;
  #define INVALID_SOCK  -1
  #define CLOSE_SOCK(s) close(s)
#endif