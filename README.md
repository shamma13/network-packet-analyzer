# PCAP Analyzer

PCAP Analyzer is a Python-based toolset for processing and analyzing network traffic captured in PCAP files. This project was done in my Data Communication and Computer Network's class and provides two main functionalities:
1. **Part 1**: Analyze network traffic for basic statistics like total packets, distinct source IPs, destination TCP ports, and source-destination pairs.
2. **Part 2**: Identify network probing and scanning attempts based on traffic patterns for TCP and UDP protocols.

## Features

### Part 1: Traffic Statistics
- Count total packets in a PCAP file.
- Extract distinct source IPs and their packet counts.
- Identify destination TCP ports and packet counts.
- List source IP and destination TCP port pairs sorted by packet counts.

### Part 2: Probing and Scanning Detection
- Identify probing attempts based on time intervals and packet counts.
- Detect scanning attempts based on target IPs, port ranges, and packet counts.
- Supports both TCP and UDP protocols.
