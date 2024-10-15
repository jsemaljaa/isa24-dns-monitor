//
// Created by Alina Vinogradova on 10/14/2024.
//

#ifndef DNS_HEADER_H
#define DNS_HEADER_H

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

    // u_char rd:1; // recursion desired
    // u_char tc:1; // truncated message
    // u_char aa:1; // authoritative answer
    // uint8_t opcode:4; // purpose of message
    // u_char qr:1; // query/response flag

    // uint8_t rcode:4; // response code
    // u_char cd:1; // checking disabled
    // u_char ad:1; // authenticated data
    // u_char z:1; // reserved for future
    // u_char ra:1; // recursion available

    uint16_t qd_count; // number of question entries
    uint16_t an_count; // number of answer entries
    uint16_t ns_count; // number of authority entries
    uint16_t ar_count; // number of additional entries
};

#endif //DNS_HEADER_H