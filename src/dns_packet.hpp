/*
 * Project: DNS Monitor
 *
 * dns_packet.h
 * Created on 14/10/2024
 * 
 * @brief Declarations of structures to extract and process data from different network layers
 *
 * @author Alina Vinogradova <xvinog00@vutbr.cz>
*/

#ifndef DNS_PACKET_H
#define DNS_PACKET_H

#include <cstdint>
#include <ctime>

// Networking (headers, macros, etc.)
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/ip6.h>

#include <string> 
#include <sstream>
#include <iomanip>
#include <queue>
#include <set>

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

// Supported DNS record types
// #define DNS_A 1
// #define DNS_NS 2
// #define DNS_CNAME 5
// #define DNS_SOA 6
// #define DNS_MX 15
// #define DNS_AAAA 28
// #define DNS_SRV 33

/*
 * Supported DNS record types
 * according to: https://datatracker.ietf.org/doc/html/rfc1035#page-12
 */
enum dns_record_types {
    DNS_A = 1, // A host address
    DNS_NS = 2, // An authoritative name server
    DNS_CNAME = 5, // The canonical name for an alias
    DNS_SOA = 6, // Marks the start of a zone of authority
    DNS_MX = 15, // Mail exchange
    DNS_AAAA = 28, // [RFC3596] A 128-bit IPv6 address
    DNS_SRV = 33, // [RFC2782] Generalized service location record
};

// Shift needed to extract exact bits from a masked part of flag
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


typedef struct dns_header {
    uint16_t id;       // identification number
    uint16_t flags;    // flags to extract with masks

    uint16_t qd_count; // number of question entries
    uint16_t an_count; // number of answer entries
    uint16_t ns_count; // number of authority entries
    uint16_t ar_count; // number of additional entries
} dns_header_t;

// Structure to parse DNS records
typedef struct dns_resource_record {
    uint16_t type;
    uint16_t class_;
    uint32_t ttl;
    uint16_t rdlength;
    uint16_t rdata;
} dns_resource_record_t;

// Special cases of DNS records: SOA and SRV
typedef struct dns_soa_record {
    uint32_t serial;
    uint32_t refresh;
    uint32_t retry;
    uint32_t expire;
    uint32_t minimum;
} dns_soa_record_t;

typedef struct dns_srv_record {
    uint16_t priority;
    uint16_t weight;
    uint16_t port;
} dns_srv_record_t;

/*
    This class is not conventional DNS header, but rather header that will suite needs 
    of this project (meaning it includes data from other network layers that we want to display
    together with DNS header information)
*/
class DnsHeader {
    public:
        uint16_t id;
        uint16_t flags;

        uint16_t qd_count;
        uint16_t an_count;
        uint16_t ns_count;
        uint16_t ar_count;

        // char src_ip[INET_ADDRSTRLEN];
        // char dst_ip[INET_ADDRSTRLEN];
        char *src_ip;
        char *dst_ip;

        uint16_t src_port;
        uint16_t dst_port;

        std::string timestamp;

        const u_char *DNSstream;
        
        /*
        * @brief Constructor for DNS Header class
        * @param dnsh - raw DNS header extracted from captured packed
        * @param udph - raw UDP header extracted from captured packed
        * @param iph  - raw IPv4 header extracted from captured packed
        * @param iph6_hdr - raw IPv6 header extracted from captured packed
        * @param ipv6 - boolean to switch between IPv4 and IPv6 header
        * @param ts - raw timestamp extracted from captured packet
        * @return DnsHeader instance
        */
        DnsHeader(dns_header_t *dnsh, struct udphdr *udph, struct ip *iph, struct ip6_hdr *ip6hdr, bool ipv6, const struct timeval ts);
        
        /*
        * @brief Extract QR flag by masking 
        * @return 16 bit value with QR flag
        */
        uint16_t get_qr();

        /*
        * @brief Extract OPCODE flag by masking 
        * @return 16 bit value with OPCODE flag
        */
		uint16_t get_opcode();
		
        /*
        * @brief Extract AA flag by masking 
        * @return 16 bit value with AA flag
        */
        uint16_t get_aa();
		
        /*
        * @brief Extract TC flag by masking 
        * @return 16 bit value with TC flag
        */
        uint16_t get_tc();
		
        /*
        * @brief Extract RD flag by masking 
        * @return 16 bit value with RD flag
        */
        uint16_t get_rd();

        /*
        * @brief Extract RA flag by masking 
        * @return 16 bit value with RA flag
        */
		uint16_t get_ra();
		
        /*
        * @brief Extract AD flag by masking 
        * @return 16 bit value with AD flag
        */
        uint16_t get_ad();
		
        /*
        * @brief Extract CD flag by masking 
        * @return 16 bit value with CD flag
        */
        uint16_t get_cd();
		
        /*
        * @brief Extract RCODE flag by masking 
        * @return 16 bit value with RCODE flag
        */
        uint16_t get_rcode();

        /*
        * @brief DnsHeader destructor 
        */
        ~DnsHeader();

    private:
        // CAUTION: convert timestamp throws segfault sometimes
        std::string convert_timestamp(const struct timeval ts);
};


class DnsPacket {
    public:
        DnsHeader *header;

        std::vector<std::string> questions;
        std::vector<std::string> answers;
        std::vector<std::string> authorities;
        std::vector<std::string> additionals;

        DnsPacket();
};

#endif //DNS_PACKET_H