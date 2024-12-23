# Network Scanner

A Python-based network scanner that enables IP and port discovery on a given network. This tool provides flexible scanning modes using ICMP and TCP protocols to identify live hosts and open ports, aiding network monitoring and security assessments.

## Features

- **ICMP Scan**: Discover live hosts using ICMP packets.
- **TCP Scan**: Discover live hosts on a specific port using TCP SYN packets.
- **Port Range Scan**: Scan a range of ports for open ones on specified hosts.
- **Detailed Reporting**: Displays live IPs and open ports for easy reference.

## Prerequisites

- **Python**: Ensure Python 3.x is installed.
- **Scapy**: Install the Scapy library by running:
  ```bash
  pip install scapy
  ```

Usage
1. Clone or download the script.
2. Run the script from a terminal:
   python network_scanner.py

3. Follow the prompts:
  Enter a valid network address in CIDR format (e.g., 192.168.1.0/24).
  Choose the mode of scanning:
    1 - ICMP Scan
    2 - TCP Scan (requires a single port number)
    3 - Port Range Scan (requires a port range
    
4. The script outputs the live hosts and open ports detected.

Code Overview
Input Validation: Ensures correct CIDR input and valid port entries.
Scanning Modes: Different scanning techniques are implemented:
  ICMP Packets for network discovery.
  TCP SYN Packets for TCP-based host discovery and port scanning.
Response Handling: Filters responses to identify live hosts and open ports.
Error Suppression: Suppresses Scapy errors for a cleaner output.

Example
For a simple ICMP scan on a /24 subnet:
  ```powershell
  Please enter the network address: 192.168.1.0/24
  Modes:
    1 - ICMP
    2 - TCP
    3 - Port Scan
  Please select the mode: 1
  192.168.1.1 is live
  192.168.1.2 is unreachable
 ```
Note:
Run with administrator/root privileges for accurate results.
Scanning a network without permission is prohibited and can be illegal. Use responsibly within your own network or with proper authorization.

This project was built to practice network scanning techniques and enhance understanding of Scapy for network automation and security tasks.

