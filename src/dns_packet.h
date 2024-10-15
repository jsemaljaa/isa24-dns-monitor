//
// Created by Alina Vinogradova on 10/14/2024.
//
#ifndef DNS_HEADER_H
#define DNS_HEADER_H

#include <cstdint>
#include <ctime>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <string> 
#include <sstream>
#include <iomanip>

/* 
    16b flags structure

    +--+--+--+--+--+--+--+-- + --+--+--+--+--+--+--+--+
    |QR|   Opcode  |AA|TC|RD | RA|   Z    |   RCODE   |
    +--+--+--+--+--+--+--+-- + --+--+--+--+--+--+--+--+

    in RFC 2065 (https://www.freesoft.org/CIE/RFC/2065/40.htm)
    AD and CD header flags are allocated from Z field

    +--+--+--+--+--+--+--+-- + --+--+--+--+--+--+--+--+
    |QR|   Opcode  |AA|TC|RD | RA| Z|AD|CD|   RCODE   |
    +--+--+--+--+--+--+--+-- + --+--+--+--+--+--+--+--+

*/


// shift needed to extract exact bits from a masked part of flag
#define MASK_FLAG(flag, mask, shift) ((flag & mask) >> shift)


// Example with 1000 0000 1000 0001 (flags == 32897)

#define QR_MASK 0x8000      // 0b1000000000000000, shift by 15
#define QR_SHIFT 15
#define OPCODE_MASK 0x3C00  // 0b0111100000000000, no shift, just masking
#define OPCODE_SHIFT 0 

#define AA_MASK 0x0400      // 0b0000010000000000, shift by 11
#define AA_SHIFT 10
#define TC_MASK 0x0200      // 0b0000001000000000
#define TC_SHIFT 9
#define RD_MASK 0x0100      // 0b0000000100000000
#define RD_SHIFT 8
#define RA_MASK 0x0080      // 0b0000000010000000
#define RA_SHIFT 7

#define Z_MASK 0x0040       // 0b0000000001000000
#define Z_SHIFT 6
#define AD_MASK 0x0020      // 0b0000000000100000
#define AD_SHIFT 5
#define CD_MASK 0x0010      // 0b0000000000010000
#define CD_SHIFT 4
#define RCODE_MASK 0x000F   // 0b0000000000001111
#define RCODE_SHIFT 0

struct dns_header {
    uint16_t id; // identification number
    uint16_t flags; // flags to extract with masks

    uint16_t qd_count; // number of question entries
    uint16_t an_count; // number of answer entries
    uint16_t ns_count; // number of authority entries
    uint16_t ar_count; // number of additional entries
};

// This class is not conventional DNS header, but rather header that will suite needs 
// of this project (meaning it includes data from other network layers that we want to display)
// together with DNS header information

class DnsHeader {
    public:
        uint16_t id;
        uint16_t flags;

        uint16_t qd_count;
        uint16_t an_count;
        uint16_t ns_count;
        uint16_t ar_count;

        char src_ip[INET_ADDRSTRLEN];
        char dst_ip[INET_ADDRSTRLEN];

        uint16_t src_port;
        uint16_t dst_port;

        std::string timestamp;

        DnsHeader(struct dns_header *dnsh, struct udphdr *udph, struct ip *iph, const struct timeval ts);
        uint16_t get_qr();
		uint16_t get_opcode();
		uint16_t get_aa();
		uint16_t get_tc();
		uint16_t get_rd();
		uint16_t get_ra();
		uint16_t get_ad();
		uint16_t get_cd();
		uint16_t get_rcode();

    private:
        std::string convert_timestamp(const struct timeval ts);
};

struct dns_question {
    uint16_t name_len;
    char name[255];
    uint16_t type;
    uint16_t qclass;
};

#endif //DNS_HEADER_H