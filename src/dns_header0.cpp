//
// Created by Alina Vinogradova on 9/21/2024.
//

#include "dns_header0.h"

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

DnsHeader::DnsHeader(struct dns_header *dnsh) {
    uint16_t flags = dnsh->flags;
    qr = get_qr(flags);
    opcode = get_opcode(flags);
    aa = get_aa(flags);
    tc = get_tc(flags);
    rd = get_rd(flags);
    ra = get_ra(flags);
    z = get_z(flags);
    ad = get_ad(flags);
    cd = get_cd(flags);
    rcode = get_rcode(flags);

    qd_count = dnsh->qd_count;
    an_count = dnsh->an_count;
    ns_count = dnsh->ns_count;
    ar_count = dnsh->ar_count;
}

// Extracting all the neccessary flags using masks

uint16_t DnsHeader::get_qr(uint16_t flags) {
    // 1st bit
    return flags & 0b1000000000000000;
}

uint8_t DnsHeader::get_opcode(uint16_t flags) {
    // 2nd bit till 5th bit
    return flags & 0b0111100000000000;
}

uint16_t DnsHeader::get_aa(uint16_t flags) {
    // 6th bit;
    return flags & 0b0000010000000000;
}

uint16_t DnsHeader::get_tc(uint16_t flags) {
    // 7th bit
    return flags & 0b0000001000000000;
}

uint16_t DnsHeader::get_rd(uint16_t flags) {
    // 8th bit
    return flags & 0b0000000100000000;
}

uint16_t DnsHeader::get_ra(uint16_t flags) {
    // 9th bit
    return flags & 0b0000000010000000;
}

uint16_t DnsHeader::get_z(uint16_t flags) {
    // 10th bit (RFC 2065)
    return flags & 0b0000000001000000;
}

uint16_t DnsHeader::get_ad(uint16_t flags) {
    // 11th bit (RFC 2065)
    return flags & 0b0000000000100000;
}

uint16_t DnsHeader::get_cd(uint16_t flags) {
    // 12th bit (RFC 2065)
    return flags & 0b0000000000010000;
}

uint8_t DnsHeader::get_rcode(uint16_t flags) {
    // 13th to 16th bit
    return flags & 0b0000000000001111;
}

