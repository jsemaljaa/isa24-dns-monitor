# dns-monitor: A DNS Monitoring Tool

This project implements a program named `dns-monitor` that monitors and analyzes DNS traffic on your network. It can either capture live traffic from a specified interface or process pre-recorded data from a PCAP file.

## Features:

- **DNS Traffic Monitoring:** Captures and processes DNS messages from network traffic.
- **Message Parsing:** Decodes and extracts information from DNS messages.
- **Domain Name Discovery:** Identifies all domain names encountered in DNS messages.
- **DNS Resolution Monitoring:** Tracks translations of domain names to IPv4/IPv6 addresses.
- **Flexible Output:** Provides information through standard output and optional output files.

## Usage:

```bash
./dns-monitor [-i <interface>] | [-p <pcapfile>] [-v] [-d <domainsfile>] [-t <translationsfile>]
```

**Parameters:**

| Parameter | Description | Default Value    |
|---|---|------------------|
| `-i <interface>` | Network interface to monitor (live traffic). | None             |
| `-p <pcapfile>` | PCAP file containing pre-recorded DNS traffic. | None             |
| `-v` | Enable verbose output with detailed message information. | Off              |
| `-d <domainsfile>` | Output file to store discovered domain names (optional). | domains.txt      |
| `-t <translationsfile>` | Output file to store domain name-to-IP translations (optional). | translations.txt |

### Example Usage:

1. **Monitor live traffic on eth0 interface:** (example interface from my Windows machine)

```bash
./dns-monitor -i eth0
```
**Monitor live traffic on enp5s0 interface:** (example interface from my Ubuntu machine)

```bash
./dns-monitor -i enp5s0
```

2. **Process data from a PCAP file named `dns_traffic.pcap`:**

```
./dns-monitor -p dns_traffic.pcap
```

3. **Capture live traffic with verbose output and save results:**

```
./dns-monitor -i eth0 -v -d observed_domains.txt -t resolved_ips.txt
```

## Functionality:

* Live Traffic Monitoring: When specified, dns-monitor captures network packets from the designated interface, filtering for those containing DNS messages.
* PCAP File Processing: If provided, the program extracts and analyzes DNS messages from the specified PCAP file.
* DNS Message Processing: It decodes the protocol information from DNS messages, extracting details like timestamp, source/destination IP addresses and ports, identifier, flags, and record section data.
* Domain Name Discovery: dns-monitor maintains a list of all unique domain names encountered in the processed messages.
* DNS Resolution Monitoring: When a DNS response includes an IP address for a domain name, the program logs the translation.
* Output: Basic information (source/destination, timestamp, query/response) is printed to standard output. 
* Optionally, discovered domain names and IP translations can be saved to separate files.

## Implementation Scope:
* This project focuses on DNS over UDP (UDP port 53) traffic.
* It supports the following DNS record types: A, AAAA, NS, MX, SOA, CNAME, and SRV.
* Support for other record types (PTR, etc.) is not included.

## Contact

[Alina Vinogradova](mailto:xvinog00@vutbr.cz)