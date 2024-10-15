//
// Created by Alina Vinogradova on 10/15/2024.
//

#include "dns_packet.h"


DnsHeader::DnsHeader(struct dns_header *dnsh, struct udphdr *udph, struct ip *iph, const struct timeval ts) {
    id = ntohs(dnsh->id);
    flags = ntohs(dnsh->flags);
    qd_count = ntohs(dnsh->qd_count);
    an_count = ntohs(dnsh->an_count);
    ns_count = ntohs(dnsh->ns_count);
    ar_count = ntohs(dnsh->ar_count);

    inet_ntop(AF_INET, &(iph->ip_src), src_ip, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(iph->ip_dst), dst_ip, INET_ADDRSTRLEN);

    src_port = ntohs(udph->source);
    dst_port = ntohs(udph->dest);

    timestamp = convert_timestamp(ts);
}

std::string DnsHeader::convert_timestamp(const struct timeval ts) {
    tm timestamp;
    localtime_r(&ts.tv_sec, &timestamp);

    std::ostringstream oss;
    oss << std::put_time(&timestamp, "%Y-%m-%d %H:%M:%S");
    return oss.str();
}


// const char* DnsHeader::get_readable_ip(struct in_addr ip) {
    // char src_ip_str[INET_ADDRSTRLEN];
    // char dst_ip_str[INET_ADDRSTRLEN];
    // inet_ntop(AF_INET, &(iph->ip_src), src_ip_str, INET_ADDRSTRLEN);
    // inet_ntop(AF_INET, &(iph->ip_dst), dst_ip_str, INET_ADDRSTRLEN);
    // char ipstr[INET_ADDRSTRLEN];
    // inet_ntop(AF_INET, ip, ipstr, INET_ADDRSTRLEN);
    // return ipstr;
// }

uint16_t DnsHeader::get_qr() {
    return MASK_FLAG(flags, QR_MASK, QR_SHIFT);
}

uint16_t DnsHeader::get_opcode() {
    return MASK_FLAG(flags, OPCODE_MASK, OPCODE_SHIFT);
}

uint16_t DnsHeader::get_aa() {
    return MASK_FLAG(flags, AA_MASK, AA_SHIFT);
}

uint16_t DnsHeader::get_tc() {
    return MASK_FLAG(flags, TC_MASK, TC_SHIFT);
}

uint16_t DnsHeader::get_rd() {
    return MASK_FLAG(flags, RD_MASK, RD_SHIFT);
}

uint16_t DnsHeader::get_ra() {
    return MASK_FLAG(flags, RA_MASK, RA_SHIFT);
}

uint16_t DnsHeader::get_ad() {
    return MASK_FLAG(flags, AD_MASK, AD_SHIFT);
}

uint16_t DnsHeader::get_cd() {
    return MASK_FLAG(flags, CD_MASK, CD_SHIFT);
}

uint16_t DnsHeader::get_rcode() {
    return MASK_FLAG(flags, RCODE_MASK, RCODE_SHIFT);
}