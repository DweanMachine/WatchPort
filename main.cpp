#include <listener.hpp>
using namespace std;

//Declaration of functions
string checkVulnerability(int port, const std::string& banner);
void drawLogo(string path);
bool port_is_open(sockaddr_in serverAddress, int port);

int main() {
  // Windows: initialize Winsock before anything else
  #ifdef _WIN32
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
      cerr << "WSAStartup failed: " << WSAGetLastError() << endl;
      return 1;
    }
  #endif
  drawLogo("assets\\logo-thin.txt");
  
  // Create a raw TCP socket
  socket_t sock = socket(AF_INET, SOCK_STREAM, 0);
  if (sock == INVALID_SOCK) {
    cerr << "Failed to create socket" << endl;
    return 1;
  }
  
  int port = 10;
  // Set up target address structure
  sockaddr_in serverAddress;
  port_is_open(serverAddress, port);

  // Connect to target
  connect(sock, (struct sockaddr*)&serverAddress, sizeof(serverAddress));
  cout << "Socket created: " << sock << std::endl;

  listen(sock, 5);
  cout << "Listening on port " + port << std::endl;
  cout << checkVulnerability(443, "OpenSSH_7.2p2");

  // Clean up
  CLOSE_SOCK(sock);
  #ifdef _WIN32
    WSACleanup();
  #endif
  return 0;
}

string checkVulnerability(int port, const string& banner) {
    vector<pair<string, string>> signatures = {
        {"vsFTPd 2.3.4",          "CVE-2011-2523: vsftpd backdoor RCE"},
        {"OpenSSH_7.2p2",         "CVE-2016-6210: OpenSSH user enumeration"},
        {"Apache/2.2.8",          "CVE-2008-0455: Apache mod_negotiation XSS"},
        {"ProFTPD 1.3.3c",        "CVE-2010-4221: ProFTPD backdoor RCE"},
        {"Sendmail 8.11.6",       "CVE-2003-0161: Sendmail remote overflow"},
        {"Microsoft-IIS/6.0",     "CVE-2017-7269: IIS 6.0 WebDAV buffer overflow"},
    };

    for (const auto& [signature, cve] : signatures) {
        if (banner.find(signature) != string::npos) {
            return "Port " + to_string(port) + " VULNERABLE - " + cve;
        }
    }
    return "Port " + std::to_string(port) + ": No vulnerabilities detected.";
}

bool port_is_open(const string& host, int port, int timeoutMs = 3000) {
  //Create socket
  socket_t sock = socket(AF_INET, SOCK_STREAM, 0);
  if (sock == INVALID_SOCK) {
    cerr << "Failed to create socket" << endl;
    return false;
  }

  //Resolve target host into address struct
  sockaddr_in serverAddress{};
  serverAddress.sin_family = AF_INET;
  serverAddress.sin_port   = htons(port);
  if (inet_pton(AF_INET, host.c_str(), &serverAddress.sin_addr) <= 0) {
    cerr << "Invalid address: " << host << endl;
    CLOSE_SOCK(sock);
    return false;
  }

  //Set non-blocking so we can enforce a timeout
    #ifdef _WIN32
        u_long mode = 1;
        ioctlsocket(sock, FIONBIO, &mode);
    #else
        fcntl(sock, F_SETFL, O_NONBLOCK);
    #endif

    //Attempt connection (returns immediately in non-blocking mode)
    connect(sock, (sockaddr*)&serverAddress, sizeof(serverAddress));

    //Use select() to wait up to timeoutMs for the connection
    fd_set fdSet;
    FD_ZERO(&fdSet);
    FD_SET(sock, &fdSet);

    timeval timeout{};
    timeout.tv_sec  = timeoutMs / 1000;
    timeout.tv_usec = (timeoutMs % 1000) * 1000;

    bool isOpen = false;
    if (select(sock + 1, nullptr, &fdSet, nullptr, &timeout) > 0) {
        // 6. Verify connection actually succeeded (select can return on error too)
        int err = 0;
        socklen_t len = sizeof(err);
        getsockopt(sock, SOL_SOCKET, SO_ERROR, (char*)&err, &len);
        isOpen = (err == 0);
    }

    CLOSE_SOCK(sock);
    return isOpen;
}

void drawLogo(string path) {
  if (!filesystem::exists(path)) {
    cout << "ERROR: No file detected!\n";
    return;
  }
  ifstream logo(path);
  string line;
  while (getline(logo, line)) {
    cout << line << "\n";
  }
  logo.close();
}