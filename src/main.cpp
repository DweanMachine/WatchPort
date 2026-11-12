#include <filesystem>
#include <fstream>
#include <iostream>
#include <string>

#include "platform.hpp"
#include "scanner.hpp"
#include "vulnerability.hpp"

namespace {

struct Options {
  std::string host;
  int firstPort = 1;
  int lastPort = 1024;
  int timeoutMs = 1000;
  int threads = 50;
};

void printUsage(const char* program) {
  std::cout << "Usage: " << program << " <host> [options]\n\n"
            << "Options:\n"
            << "  -p <range>    Port or range to scan, e.g. 80 or 1-1024 (default: 1-1024)\n"
            << "  -t <ms>       Connection timeout in milliseconds (default: 1000)\n"
            << "  -j <threads>  Number of worker threads (default: 50)\n"
            << "  -h, --help    Show this message\n\n"
            << "Only scan systems you own or have explicit permission to test.\n";
}

void printLogo(const std::string& path) {
  std::ifstream logo(path);
  if (!logo) return;  // The logo is decorative; skip it quietly if it is missing
  std::string line;
  while (std::getline(logo, line)) std::cout << line << '\n';
  std::cout << '\n';
}

bool parsePortRange(const std::string& text, Options& options) {
  try {
    size_t used = 0;
    int first = std::stoi(text, &used);
    int last = first;
    if (used < text.size()) {
      if (text[used] != '-') return false;
      last = std::stoi(text.substr(used + 1));
    }
    if (first < 1 || last > 65535 || first > last) return false;
    options.firstPort = first;
    options.lastPort = last;
    return true;
  } catch (const std::exception&) {
    return false;
  }
}

bool parsePositiveInt(const std::string& text, int& value) {
  try {
    size_t used = 0;
    int parsed = std::stoi(text, &used);
    if (used != text.size() || parsed < 1) return false;
    value = parsed;
    return true;
  } catch (const std::exception&) {
    return false;
  }
}

// Returns 0 on success, 1 on a usage error, -1 if help was requested.
int parseArguments(int argc, char** argv, Options& options) {
  for (int i = 1; i < argc; i++) {
    std::string arg = argv[i];
    if (arg == "-h" || arg == "--help") return -1;

    bool needsValue = (arg == "-p" || arg == "-t" || arg == "-j");
    if (needsValue) {
      if (i + 1 >= argc) {
        std::cerr << "Missing value for " << arg << '\n';
        return 1;
      }
      std::string value = argv[++i];
      bool ok = (arg == "-p")   ? parsePortRange(value, options)
                : (arg == "-t") ? parsePositiveInt(value, options.timeoutMs)
                                : parsePositiveInt(value, options.threads);
      if (!ok) {
        std::cerr << "Invalid value for " << arg << ": " << value << '\n';
        return 1;
      }
    } else if (!arg.empty() && arg[0] == '-') {
      std::cerr << "Unknown option: " << arg << '\n';
      return 1;
    } else if (options.host.empty()) {
      options.host = arg;
    } else {
      std::cerr << "Unexpected argument: " << arg << '\n';
      return 1;
    }
  }
  if (options.host.empty()) {
    std::cerr << "No host specified.\n";
    return 1;
  }
  return 0;
}

}  // namespace

int main(int argc, char** argv) {
  Options options;
  int parsed = parseArguments(argc, argv, options);
  if (parsed != 0) {
    printUsage(argv[0]);
    return parsed < 0 ? 0 : 1;
  }

  try {
    NetworkSession network;  // Winsock setup/teardown on Windows

    printLogo("assets/logo-thin.txt");

    sockaddr_in address{};
    if (!resolveHost(options.host, address)) {
      std::cerr << "Could not resolve host: " << options.host << '\n';
      return 1;
    }

    std::cout << "Scanning " << options.host << " ports " << options.firstPort << "-"
              << options.lastPort << "...\n\n";

    auto results = scanRange(address, options.firstPort, options.lastPort, options.timeoutMs,
                             options.threads);

    int openCount = 0;
    int findings = 0;
    for (const auto& result : results) {
      if (!result.open) continue;
      openCount++;
      std::cout << "Port " << result.port << " open";
      if (!result.banner.empty()) std::cout << "  [" << result.banner << "]";
      std::cout << '\n';

      if (auto finding = checkVulnerability(result.banner)) {
        findings++;
        std::cout << "  ! Known vulnerability: " << *finding << '\n';
      }
    }

    std::cout << "\nScan complete: " << openCount << " open port(s), " << findings
              << " potential finding(s).\n";
    return 0;
  } catch (const std::exception& error) {
    std::cerr << "Error: " << error.what() << '\n';
    return 1;
  }
}
