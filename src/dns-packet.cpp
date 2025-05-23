/*
 * Project: DNS Monitor
 *
 * dns_packet.cpp
 * Created on 15/10/2024
 * 
 * @brief Implementation of helper methods to extract data from different network layers
 *
 * @author Alina Vinogradova <xvinog00@vutbr.cz>
*/


#include "dns-packet.hpp"

DnsHeader::DnsHeader(dns_header_t *dnsh, struct udphdr *udph, struct ip *iph, struct ip6_hdr *ip6hdr, bool ipv6, const struct timeval ts) {
    id = ntohs(dnsh->id);
    flags = ntohs(dnsh->flags);
    qd_count = ntohs(dnsh->qd_count);
    an_count = ntohs(dnsh->an_count);
    ns_count = ntohs(dnsh->ns_count);
    ar_count = ntohs(dnsh->ar_count);

    if (!ipv6) {
        src_ip = new char[INET_ADDRSTRLEN];
        dst_ip = new char[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &(iph->ip_src), src_ip, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, &(iph->ip_dst), dst_ip, INET_ADDRSTRLEN);
    } else {
        src_ip = new char[INET6_ADDRSTRLEN];
        dst_ip = new char[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, &(ip6hdr->ip6_src), src_ip, INET6_ADDRSTRLEN);
        inet_ntop(AF_INET6, &(ip6hdr->ip6_dst), dst_ip, INET6_ADDRSTRLEN);
    }

    src_port = ntohs(udph->source);
    dst_port = ntohs(udph->dest);

    timestamp = convert_timestamp(ts);
}

DnsHeader::~DnsHeader() {
    delete[] src_ip;
    delete[] dst_ip;
}

std::string DnsHeader::convert_timestamp(const struct timeval ts) {
    tm timestamp;
    localtime_r(&ts.tv_sec, &timestamp);

    std::ostringstream oss;
    oss << std::put_time(&timestamp, "%Y-%m-%d %H:%M:%S");

    return oss.str();
}


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

DnsPacket::DnsPacket() {

}