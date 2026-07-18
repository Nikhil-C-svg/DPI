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


## Acknowledgments
The foundational packet processing architecture (L2-L4 parsing) of this engine is based on network engineering concepts presented by Pratyush Narain. Additionally, AI tools were heavily utilized to assist with debugging, configuring the CMake build environment, and understanding advanced multi-threading integrations.