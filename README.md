# WHS_network_security
PCAP TCP Packet Sniffer

# TCP Packet Sniffer using PCAP API

This is a simple C-based packet sniffer developed for a network security assignment.  
It captures TCP packets using the PCAP API, parses Ethernet/IP/TCP headers, and optionally displays payload data.

## Features

- Captures only **TCP** packets (UDP/ICMP are ignored)
- Parses and displays:
  - Source & destination MAC addresses (Ethernet)
  - Source & destination IP addresses (IP)
  - Source & destination ports (TCP)
  - Payload data (up to 32 bytes, printable characters only)
- Accurately uses IP and TCP header length fields
- Works in Linux environments (tested on Ubuntu 24.04 in VirtualBox)

## Files Included

- `yunji_sniff.c` — main source file
- `README.md` — project description

## Requirements

- GCC compiler
- libpcap development library

Install dependencies:

```bash
sudo apt update
sudo apt install -y libpcap-dev build-essential
