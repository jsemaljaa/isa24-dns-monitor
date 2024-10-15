
Implement a program `dns-monitor` that monitors DNS communication on a selected interface or processes DNS messages from an existing communication record in PCAP format.

The tool will process DNS protocol messages and display information derived from them. Furthermore, the tool will be able to detect what domain names appeared in the DNS messages. The third functionality is finding the translation of domain names to IPv4/6 addresses.

The program has three possible outputs:

* Standard output with information about DNS messages,
* (optionally) a file with observed domain names, and
* (optionally) a file with the translations of domain names to IP addresses.

## Execution Syntax

```
./dns-monitor (-i <interface> | -p <pcapfile>) [-v] [-d <domainsfile>] [-t <translationsfile>]
```

## Parameters

| Parameter | Description |
| --------- | ----------- |
| `-i <interface>` | The name of the interface on which the program will listen, or |
| `-r <pcapfile>` | The name of the PCAP file the program will process; |
| `-v` | "Verbose" mode: a complete output of DNS message details; |
| `-d <domainsfile>` | The name of the file with domain names; |
| `-t <translationsfile>` | The name of the file with the translations of domain names to IP. |

## Functionality Description

The program will read network packets from the input (network interface, PCAP file) and process DNS protocol messages.

## Implementation Scope:

For the purposes of the project, support for **DNS** over **UDP** protocol is sufficient. It is also enough for the program to support the following record types: A, AAAA, NS, MX, SOA, CNAME, SRV. Support for other record types (PTR, etc.) is not required (i.e., the tool may ignore them).

## The program will ensure the following functionality:

A) Displaying information about DNS messages;  
B) Searching for domain names;  
C) Searching for translations of domain names to IPv4/6 addresses.

The following are details on each function of the program.

### Displaying Information About DNS Messages

The program will print information about observed DNS messages to the standard output based on the parameters. Without the `-v` parameter, only the summary will be displayed:

```
2024-09-17 14:42:10 192.168.1.5 -> 8.8.8.8 (Q 1/0/0/0)
2024-09-17 14:42:11 8.8.8.8 -> 192.168.1.5 (R 1/1/2/2)
```

With the `-v` parameter, the following detailed information will be displayed:

```
Timestamp: 2024-09-17 14:42:10
SrcIP: 192.168.1.5
DstIP: 8.8.8.8
SrcPort: UDP/54321
DstPort: UDP/53
Identifier: 0xA1B2
Flags: QR=0, OPCODE=0, AA=0, TC=0, RD=1, RA=0, AD=0, CD=0, RCODE=0

[Question Section]
google.com. IN A.
====================
```

(Reply appears.)

### Searching for Domain Names

The program will create a list of all domain names that appeared in DNS messages.

### Searching for Translations of Domain Names to IPv4/6 Addresses

The program will display a list of translations of domain names to IP addresses.

### Example Run 1:

```
./dns-monitor -i eth0
```
(A query for an A record for google.com appears.)

```
2024-09-17 14:42:10 192.168.1.5 -> 8.8.8.8 (Q 1/0/0/0)
(Reply appears.)
2024-09-17 14:42:11 8.8.8.8 -> 192.168.1.5 (R 1/1/2/2)
```

### Example Run 2:

```
./dns-monitor -i eth0 -v
```

(A query for an A record for google.com appears.)

```
Timestamp: 2024-09-17 14:42:10
SrcIP: 192.168.1.5
DstIP: 8.8.8.8
...
====================
```

### Example Run 3:

```
(We run the program in the background and enter other commands.)
./dns-monitor -i eth0 -d domains.txt -t translations.txt &
nslookup seznam.cz
```

```
cat domains.txt
seznam.cz
cat translations.txt
seznam.cz 77.75.79.222
```

Recommended sources:

RFC 1035  
RFC 3596  
Sample code examples on the Moodle of the ISA course.

---