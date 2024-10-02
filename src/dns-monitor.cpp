//
// Created by Alina Vinogradova on 9/21/2024.
//

#include "dns-monitor.h"

// g++ -o dns-monitor dns-monitor.cpp -lpcap

void print_debug(const char *message) {
    std::cout << message << std::endl;
}

parameters get_app_config(int argc, char *argv[]) {
    parameters config = parse(argc, argv);
    if (!config.interface.empty()) {
        std::cout << "Interface: " << config.interface << std::endl;
    }

    if (!config.pcapfile.empty()) {
        std::cout << "PCAP File: " << config.pcapfile << std::endl;
    }

    if (config.verbose) {
        std::cout << "Verbose Mode: ON" << std::endl;
    }

    if (!config.domainsfile.empty()) {
        std::cout << "Domains File: " << config.domainsfile << std::endl;
    }

    if (!config.translationsfile.empty()) {
        std::cout << "Translations File: " << config.translationsfile << std::endl;
    }

    return config;
}

void print_udphdr(struct udphdr *udph) {
    std::cout << "UDP Header:" << std::endl;
    std::cout << '\t' << "Source port: " << ntohs(udph->source) << std::endl;
    std::cout << '\t' << "Destination port: " << ntohs(udph->dest) << std::endl;
    std::cout << '\t' << "Length: " << ntohs(udph->len) << std::endl;
    std::cout << '\t' << "Checksum: " << ntohs(udph->check) << std::endl;
}

void display_dns_packet(struct dns_header *dnshdr, struct udphdr *udph, struct ip *iph, bool verbose) {
    time_t now = time(0);
    tm *t = localtime(&now);
    auto tmstmp = std::put_time(t, "%Y-%m-%d %H:%M:%S");

    char src_ip_str[INET_ADDRSTRLEN];
    char dst_ip_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(iph->ip_src), src_ip_str, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(iph->ip_dst), dst_ip_str, INET_ADDRSTRLEN);

    // Extract individual flags from the DNS flags field

    if (verbose) {
        std::cout << "Timestamp: " << tmstmp << std::endl;
        std::cout << "SrcIP: " << src_ip_str << std::endl;
        std::cout << "DstIP: " << dst_ip_str << std::endl;
        std::cout << "SrcPort: UDP/" << ntohs(udph->source) << std::endl;
        std::cout << "DstPort: UDP/" << ntohs(udph->dest) << std::endl;
        std::cout << "Identifier: " << std::hex << std::uppercase << "0x" << dnshdr->id << std::endl;
        std::cout << "Flags: QR=" << dnshdr->qr << ", OPCODE=" << dnshdr->opcode << ", AA=" << dnshdr->AA << ", TC=" << dnshdr->TC << ", RD=" << dnshdr->RD << ", RA=" << dnshdr->RA << ", AD=" << dnshdr->AD << ", CD=" << dnshdr->CD << ", RCODE=" << dnshdr->rcode << std::endl;
        // Flags: QR=1, OPCODE=0, AA=1, TC=0, RD=1, RA=1, AD=0, CD=0, RCODE=0

        

        // also add answers
        // [Question Section]
        // google.com. IN A

        // [Answer Section]
        // google.com. 300 IN A 142.250.183.142

        // [Authority Section]
        // google.com. 86400 IN NS ns1.google.com.
        // google.com. 86400 IN NS ns2.google.com.

        // [Additional Section]
        // ns1.google.com. 86400 IN A 216.239.32.10
        // ns2.google.com. 86400 IN A 216.239.34.10
        // ====================


        // id - hex 16bit
        // std::cout << '\t' << "ID " << dnshdr->id << std::endl;
        // std::cout << '\t' << "Flags " << dnshdr->flags << std::endl;
        std::cout << '\t' << "Questions count " << dnshdr->qd_count << std::endl;
        std::cout << '\t' << "Answers count " << dnshdr->an_count << std::endl;
        std::cout << '\t' << "Authority count " << dnshdr->ns_count << std::endl;
        std::cout << '\t' << "Additionals count " << dnshdr->ar_count << std::endl;
        std::cout << "====================" << std::endl;
    }
}

void packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {

    // https://github.com/packetzero/dnssniffer/blob/master/src/main.cpp#L166C3-L166C114

    std::cout << "Caplen: " << header->caplen << " Len: " << header->len << std::endl;

    if (header->caplen < header->len) {
        std::cout <<" Truncated packet" << header->len << "/" << header->caplen << "bytes" << std::endl;
    }

    struct ip *iph = (struct ip *)(packet + SIZE_ETHERNET_HDR); // Skip 14 bytes of ethernet header 

    struct udphdr *udph = (struct udphdr *)(packet + SIZE_ETHERNET_HDR + iph->ip_hl * 4);

    std::cout << std::endl << "UDP: " << sizeof(struct udphdr) << "b IP: " << iph->ip_hl * 4 << "b"<< std::endl;

    struct dns_header *dnshdr = (struct dns_header *)(packet + iph->ip_hl * 4 + sizeof(struct udphdr));

    // print_udphdr(udph);
    
    // dig -p 53 domain.com @8.8.8.8

    // 17 corresponds to UDP protocol
    display_dns_packet(dnshdr, udph, iph, true);

}


int main(int argc, char* argv[]) {

    std::cout << (__BYTE_ORDER == __BIG_ENDIAN ? "BIG_ENDIAN" : "LITTLE_ENDIAN") << std::endl;

    parameters config = get_app_config(argc, argv);

    pcap_t *handle = nullptr;
    char errbuf[PCAP_ERRBUF_SIZE];

    if (!config.interface.empty()) {
        handle = pcap_open_live(config.interface.c_str(), BUFSIZ, 1, 1000, errbuf);
    } else if (!config.pcapfile.empty()) {
        // handle = pcap_open_offline(pcapfile, errbuf);
    } else {
        // Technically not possible, but to avoid unexpected behaviour
        std::cerr << "Error: You must specify either an interface (-i) or a PCAP file (-p). (but not both)\n";
        exit(EXIT_FAILURE);
    }

    if (handle == nullptr) {
        fprintf(stderr, "Something went wrong: %s\n", errbuf);
        exit(EXIT_FAILURE);
    }

    /* PCAP FILTER */
    char filter[] = "udp port 53";
    struct bpf_program fp;
    bpf_u_int32 net;

    if (pcap_compile(handle, &fp, filter, 0, net) == -1) {
        fprintf(stderr, "Error compiling filter: %s\n", pcap_geterr(handle));
        exit(EXIT_FAILURE);
    }

    if (pcap_setfilter(handle, &fp) == -1) {
	    fprintf(stderr, "Error setting filter: %s\n", pcap_geterr(handle));
        exit(EXIT_FAILURE);
    }

    std::cout << "Applied filter: " << filter << std::endl;

    pcap_loop(handle, -1, packet_handler, nullptr);

    return 0;
}
