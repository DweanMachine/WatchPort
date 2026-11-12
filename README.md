# WatchPort

A command-line TCP port scanner that identifies open ports, reads service banners, and flags
services whose banners match a short list of known-vulnerable versions.

> **Use responsibly.** Only scan systems you own or have explicit, written permission to test.
> Unauthorized scanning may violate law or policy.

## Features
- Multi-threaded TCP connect scanning with a configurable timeout
- Banner grabbing for services that announce themselves (SSH, FTP, SMTP, ...)
- Banner-based matching against known CVEs
- Windows, Linux and macOS support

## Build
Requires a C++17 compiler and CMake 3.16 or newer.

```
cmake -S . -B build
cmake --build build
```

## Usage
```
watchport <host> [-p <range>] [-t <ms>] [-j <threads>]
```

| Option | Description | Default |
| --- | --- | --- |
| `-p <range>` | Port or range, e.g. `80` or `1-1024` | `1-1024` |
| `-t <ms>` | Connection timeout in milliseconds | `1000` |
| `-j <threads>` | Worker threads | `50` |

Example:
```
watchport 192.168.1.10 -p 1-1024
```

## Limitations
Vulnerability detection compares banners against a small built-in list (`src/vulnerability.cpp`).
It is a heuristic: services that hide or alter their banners will be missed, and patched software
that keeps an old version string may be flagged incorrectly. It is not a replacement for a full
vulnerability scanner.

## Project layout
- `src/main.cpp` - argument parsing and output
- `src/scanner.*` - port scanning and banner grabbing
- `src/vulnerability.*` - known-vulnerability signatures
- `src/platform.hpp` - Windows / POSIX socket abstraction
- `assets/` - ASCII logo
