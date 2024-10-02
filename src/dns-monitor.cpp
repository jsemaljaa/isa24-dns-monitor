//
// Created by Alina Vinogradova on 9/21/2024.
//

#include "dns-monitor.h"

// g++ -o dns-monitor dns-monitor.cpp -lpcap

void print_debug(const char *message) {
    std::cout << message << '\n';
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
    std::cout << "UDP Header:" << '\n';
    std::cout << '\t' << "Source port: " << ntohs(udph->source) << '\n';
    std::cout << '\t' << "Destination port: " << ntohs(udph->dest) << '\n';
    std::cout << '\t' << "Length: " << ntohs(udph->len) << '\n';
    std::cout << '\t' << "Checksum: " << ntohs(udph->check) << '\n';
}

void display_dns_packet(struct dns_header *dnshdr, bool verbose) {
    if (verbose) {
        // id - hex 16bit
        std::cout << '\t' << "ID " << dnshdr->id << '\n';
        std::cout << '\t' << "Flags " << dnshdr->flags << '\n';
        std::cout << '\t' << "Questions count " << dnshdr->qd_count << '\n';
        std::cout << '\t' << "Answers count " << dnshdr->an_count << '\n';
        std::cout << '\t' << "Authority count " << dnshdr->ns_count << '\n';
        std::cout << '\t' << "Additionals count " << dnshdr->ar_count << '\n';
    }
}

void packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {

    // https://github.com/packetzero/dnssniffer/blob/master/src/main.cpp#L166C3-L166C114
    if (header->caplen < header->len) printf("Truncated packet %d -> %d bytes\n", header->len, header->caplen);

    struct iphdr *iph = (struct iphdr *)(packet + SIZE_ETHERNET_HDR); // Skip 14 bytes of ethernet header 
    int ip_header_len = iph->ihl * 4;

    struct udphdr *udph = (struct udphdr *)(packet + SIZE_ETHERNET_HDR + ip_header_len);

    struct dns_header *dnshdr = (struct dns_header *)(packet + ip_header_len + sizeof(struct udphdr));

    print_udphdr(udph);
    
    // dig -p 53 domain.com @8.8.8.8

    // 17 corresponds to UDP protocol
    // if (iph->protocol == 17) {
        std::cout << "### CAPTURED DNS HEADER ###" << '\n';
        display_dns_packet(dnshdr, true);
    // }
}


int main(int argc, char* argv[]) {
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

    std::cout << filter << '\n';

    pcap_loop(handle, -1, packet_handler, nullptr);

    return 0;
}
