# Deep Packet Inspection (DPI) Engine

**Developer:** Nikhil  
**Institution:** BMS College of Engineering (BMSCE) - Electronics and Communication Engineering

## Overview
This project is a custom, multi-threaded Deep Packet Inspection (DPI) Engine written in C++. It acts as a network traffic analyzer and firewall by programmatically dissecting `.pcap` network traffic layer-by-layer (L2-L4). It actively inspects Application Layer (L7) payloads to extract Server Name Indication (SNI) data, allowing for advanced traffic filtering, application identification, and domain-level blocking.

## Architecture
* **Layer 2 (Data Link):** Parses Ethernet headers to process MAC addresses.
* **Layer 3 (Network):** Analyases IPv4 headers for accurate packet routing and source/destination IP tracking.
* **Layer 4 (Transport):** Monitors TCP/UDP headers, sequence numbers, and actively tracks the TCP 3-way handshake to manage connection flows.
* **Layer 7 (Application):** Performs deep inspection on TLS Client Hello packets to extract unencrypted domain names (SNI) prior to HTTPS encryption.

## Browser dashboard

The dashboard runs on your computer and calls the same C++ packet analyzer as the command line. Choose a capture or click **Analyze sample capture**, add optional blocking rules, review packet totals and detected hostnames, then download the output PCAP.

From the repository root in PowerShell, with CMake, Visual Studio Build Tools with Desktop development with C++, and Python 3 installed:

```powershell
cmake -S . -B build-dashboard
cmake --build build-dashboard --config Release
py -3 .\dashboard\server.py --engine .\build-dashboard\Release\packet_analyzer.exe
```

Open **http://127.0.0.1:8000**. In a single-configuration build such as MinGW, pass `.\build-dashboard\packet_analyzer.exe` as the engine path. On Linux or macOS, use `python3 dashboard/server.py --engine ./build-dashboard/packet_analyzer` after building with a single-configuration generator.

The dashboard accepts little-endian, microsecond-resolution Ethernet PCAP files (v2.4) up to 16 MiB. The engine analyzes IPv4 TCP and UDP packets, and blocking rules apply to the exported file. The server listens on loopback and removes its temporary capture files when analysis finishes.

## Build Instructions
This project utilizes CMake for cross-platform compilation. 
-----------------------------------------------------
## Command line useage
```bash
mkdir build
cd build
cmake ..
cmake --build .

./packet_analyzer <input.pcap> <output.pcap> [options]

Options:
  --block-ip <ip>          Block a specific source IP
  --block-app <app>        Block application (e.g., YouTube, Facebook)
  --block-domain <dom>     Block domain (substring match)
```

## Acknowledgments
The foundational packet processing architecture (L2-L4 parsing) of this engine is based on network engineering concepts presented by Pratyush Narain. Additionally, AI tools were heavily utilized to assist with debugging, configuring the CMake build environment, and understanding advanced multi-threading integrations.
