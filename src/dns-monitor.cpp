//
// Created by Alina Vinogradova on 9/21/2024.
//

#include "dns-monitor.h"

using namespace std;

// g++ -o dns-monitor dns-monitor.cpp -lpcap

void print_debug(const char *message) {
    cout << message << endl;
}

parameters get_app_config(int argc, char *argv[]) {
    parameters config = parse(argc, argv);
    if (!config.interface.empty()) {
        cout << "Interface: " << config.interface << endl;
    }

    if (!config.pcapfile.empty()) {
        cout << "PCAP File: " << config.pcapfile << endl;
    }

    if (config.verbose) {
        cout << "Verbose Mode: ON" << endl;
    }

    if (!config.domainsfile.empty()) {
        cout << "Domains File: " << config.domainsfile << endl;
    }

    if (!config.translationsfile.empty()) {
        cout << "Translations File: " << config.translationsfile << endl;
    }

    return config;
}

void print_udphdr(struct udphdr *udph) {
    cout << "UDP Header:" << endl;
    cout << '\t' << "Source port: " << ntohs(udph->source) << endl;
    cout << '\t' << "Destination port: " << ntohs(udph->dest) << endl;
    cout << '\t' << "Length: " << ntohs(udph->len) << endl;
    cout << '\t' << "Checksum: " << ntohs(udph->check) << endl;
}

void display_dns_packet(dns_header *dnsh, struct udphdr *udph, struct ip *iph, struct tm ts, bool verbose) {

    char src_ip_str[INET_ADDRSTRLEN];
    char dst_ip_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(iph->ip_src), src_ip_str, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(iph->ip_dst), dst_ip_str, INET_ADDRSTRLEN);

    dnsh->flags = ntohs(dnsh->flags);
    dnsh->qd_count = ntohs(dnsh->qd_count);
    dnsh->an_count = ntohs(dnsh->an_count);
    dnsh->ns_count = ntohs(dnsh->ns_count);
    dnsh->ar_count = ntohs(dnsh->ar_count);

    // Extract individual flags from the DNS flags field

    if (verbose) {
        cout << "Timestamp: " << put_time(&ts, "%Y-%m-%d %H:%M:%S") << endl;
        cout << "SrcIP: " << src_ip_str << endl;
        cout << "DstIP: " << dst_ip_str << endl;
        cout << "SrcPort: UDP/" << ntohs(udph->source) << endl;
        cout << "DstPort: UDP/" << ntohs(udph->dest) << endl;
        // cout << "Identifier: " << hex << uppercase << "0x" << ntohs(dnsh->id) << endl;
        cout << "Identifier: " << ntohs(dnsh->id) << endl;
        cout << "Flags: ";
            cout << "QR=" << MASK_FLAG(dnsh->flags, QR_MASK, QR_SHIFT) << ", ";
            cout << "OPCODE=" << MASK_FLAG(dnsh->flags, OPCODE_MASK, OPCODE_SHIFT) << ", ";
            cout << "AA=" << MASK_FLAG(dnsh->flags, AA_MASK, AA_SHIFT) << ", ";
            cout << "TC=" << MASK_FLAG(dnsh->flags, TC_MASK, TC_SHIFT) << ", ";
            cout << "RD=" << MASK_FLAG(dnsh->flags, RD_MASK, RD_SHIFT) << ", ";
            cout << "RA=" << MASK_FLAG(dnsh->flags, RA_MASK, RA_SHIFT) << ", ";
            cout << "AD=" << MASK_FLAG(dnsh->flags, AD_MASK, AD_SHIFT) << ", ";
            cout << "CD=" << MASK_FLAG(dnsh->flags, CD_MASK, CD_SHIFT) << ", ";
            cout << "RCODE=" << MASK_FLAG(dnsh->flags, RCODE_MASK, RCODE_SHIFT) << endl;
        
        cout << endl; 

        cout << "[Question Section]" << endl;
        // google.com. IN A
        cout << endl; 

        cout << "[Answer Section]" << endl;
        // google.com. 300 IN A 142.250.183.142
        cout << endl; 

        cout << "[Authority Section]" << endl;
        // google.com. 86400 IN NS ns1.google.com.
        // google.com. 86400 IN NS ns2.google.com.
        cout << endl; 

        cout << "[Additional Section]" << endl;
        // ns1.google.com. 86400 IN A 216.239.32.10
        // ns2.google.com. 86400 IN A 216.239.34.10
        cout << endl; 

        // cout << '\t' << "Questions count " << dnshdr->qd_count << endl;
        // cout << '\t' << "Answers count " << dnshdr->an_count << endl;
        // cout << '\t' << "Authority count " << dnshdr->ns_count << endl;
        // cout << '\t' << "Additionals count " << dnshdr->ar_count << endl;
        cout << "====================" << endl;
    } else {
        cout << put_time(&ts, "%Y-%m-%d %H:%M:%S") << " ";
        cout << src_ip_str << " -> " << dst_ip_str << " ";
        cout << "(" << ((MASK_FLAG(dnsh->flags, QR_MASK, QR_SHIFT) == 1) ? "R" : "Q") << " ";
        cout << dnsh->qd_count << "/";
        cout << dnsh->an_count << "/";
        cout << dnsh->ns_count << "/";
        cout << dnsh->ar_count << ")" << endl;
    }
}

struct tm printable_timestamp_from_timeval(const struct timeval ts) {
    tm timestamp;
    localtime_r(&ts.tv_sec, &timestamp);

    return timestamp;
}

void packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {

    unsigned int offset = 0;

    struct tm packet_timestamp = printable_timestamp_from_timeval(header->ts); 

    cout << "Caplen: " << header->caplen << " // Len: " << header->len << endl;

    // https://github.com/packetzero/dnssniffer/blob/master/src/main.cpp#L166C3-L166C114
    if (header->caplen < header->len) {
        cout <<" Truncated packet: " << header->len << " / " << header->caplen << " bytes" << endl;
    }

    offset += SIZE_ETHERNET_HDR;
    struct ip *iph = (struct ip *)(packet + offset);

    // + 28?

    offset += iph->ip_hl * 4;

    struct udphdr *udph = (struct udphdr *)(packet + offset);
    // udph = (struct udphdr *)(packet + 28);
    
    offset += sizeof(udph);

    struct dns_header *dnshdr = (struct dns_header *)(packet + offset);
    
    
    display_dns_packet(dnshdr, udph, iph, packet_timestamp, true);

    // https://github.com/jsemaljaa/ipk22-projects/blob/main/Proj2/ipk-sniffer.c#L311


    // dig -p 53 domain.com @8.8.8.8


    // iph = (struct ip *)(packet + SIZE_ETHERNET_HDR); // Skip 14 bytes of ethernet header 
    // udph = (struct udphdr *)(packet + SIZE_ETHERNET_HDR + iph->ip_hl * 4);
    // 17 corresponds to UDP protocol
}


int main(int argc, char* argv[]) {

    cout << "Byte order: " << (__BYTE_ORDER == __BIG_ENDIAN ? "BIG_ENDIAN" : "LITTLE_ENDIAN") << endl;

    parameters config = get_app_config(argc, argv);

    pcap_t *handle = nullptr;
    char errbuf[PCAP_ERRBUF_SIZE];

    if (!config.interface.empty()) {
        handle = pcap_open_live(config.interface.c_str(), BUFSIZ, 1, 1000, errbuf);
    } else if (!config.pcapfile.empty()) {
        // handle = pcap_open_offline(pcapfile, errbuf);
    } else {
        // Technically not possible, but to avoid unexpected behaviour
        cerr << "Error: You must specify either an interface (-i) or a PCAP file (-p). (but not both)\n";
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

    cout << "Applied filter: " << filter << endl;

    pcap_loop(handle, -1, packet_handler, nullptr);

    return 0;
}
