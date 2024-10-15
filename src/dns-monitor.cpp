//
// Created by Alina Vinogradova on 9/21/2024.
//

#include "dns-monitor.h"

using namespace std;

// g++ -o dns-monitor dns-monitor.cpp -lpcap


// https://en.wikipedia.org/wiki/List_of_DNS_record_types
const char *parse_dns_question_type(uint16_t type) {
    switch (type) {
    case 1:
        return "A";
    case 2:
        return "NS";
    case 5:
        return "CNAME";
    case 6:
        return "SOA";
    case 15:
        return "MX";
    case 28:
        return "AAAA";
    case 33:
        return "SRV";    
    default:
        return "UNKNWN";
    }
}

const char *parse_dns_question_class(uint16_t qclass) {
    switch (qclass) {
    case 1:
        return "IN";
    default:
        return "UNKNWN";
    }
}

void print_debug(const char *message) {
    cout << message << endl;
}

parameters get_app_config(int argc, char *argv[]) {
    parameters config = parse(argc, argv);
    // if (!config.interface.empty()) {
    //     cout << "Interface: " << config.interface << endl;
    // }

    // if (!config.pcapfile.empty()) {
    //     cout << "PCAP File: " << config.pcapfile << endl;
    // }

    // if (config.verbose) {
    //     cout << "Verbose Mode: ON" << endl;
    // }

    // if (!config.domainsfile.empty()) {
    //     cout << "Domains File: " << config.domainsfile << endl;
    // }

    // if (!config.translationsfile.empty()) {
    //     cout << "Translations File: " << config.translationsfile << endl;
    // }

    return config;
}

void print_udphdr(struct udphdr *udph) {
    cout << "UDP Header:" << endl;
    cout << '\t' << "Source port: " << ntohs(udph->source) << endl;
    cout << '\t' << "Destination port: " << ntohs(udph->dest) << endl;
    cout << '\t' << "Length: " << ntohs(udph->len) << endl;
    cout << '\t' << "Checksum: " << ntohs(udph->check) << endl;
}

void display_dns_packet(dns_header *dnsh) {

    // for (int i = 0; i < dnsh->qd_count; i++) {
        // struct dns_question *dnsq = (struct dns_question *)(dnsh + )
    // }

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

    
}

void display_dns_packet(DnsHeader dnsh, bool verbose) {

    if (verbose) {
        cout << "Timestamp: " << dnsh.timestamp << endl;
        cout << "SrcIP: " << dnsh.src_ip << endl;
        cout << "DstIP: " << dnsh.dst_ip << endl;
        cout << "SrcPort: UDP/" << dnsh.src_port << endl;
        cout << "DstPort: UDP/" << dnsh.dst_port << endl;
        // cout << "Identifier: " << hex << uppercase << "0x" << ntohs(dnsh->id) << endl;
        cout << "Identifier: " << dnsh.id << endl;
        cout << "Flags: ";
            cout << "QR=" << dnsh.get_qr() << ", ";
            cout << "OPCODE=" << dnsh.get_opcode() << ", ";
            cout << "AA=" << dnsh.get_aa() << ", ";
            cout << "TC=" << dnsh.get_tc() << ", ";
            cout << "RD=" << dnsh.get_rd() << ", ";
            cout << "RA=" << dnsh.get_ra() << ", ";
            cout << "AD=" << dnsh.get_ad() << ", ";
            cout << "CD=" << dnsh.get_cd() << ", ";
            cout << "RCODE=" << dnsh.get_rcode() << endl;
        
        cout << endl; 

        cout << "[Question Section]" << endl;

        for (; !dnsh.questions.empty(); dnsh.questions.pop()) {
            cout << dnsh.questions.front();
        }
        cout << endl; 
        // display_dns_packet(dnsh);

        // cout << '\t' << "Questions count " << dnsh.qd_count << endl;
        // cout << '\t' << "Answers count " << dnsh.an_count << endl;
        // cout << '\t' << "Authority count " << dnsh.ns_count << endl;
        // cout << '\t' << "Additionals count " << dnsh.ar_count << endl;
        cout << "====================" << endl;
    } else {
        cout << dnsh.timestamp << " ";
        cout << dnsh.src_ip << " -> " << dnsh.dst_ip << " ";
        cout << "(" << ((dnsh.get_qr() == 1) ? "R" : "Q") << " ";
        cout << dnsh.qd_count << "/";
        cout << dnsh.an_count << "/";
        cout << dnsh.ns_count << "/";
        cout << dnsh.ar_count << ")" << endl;
    }
}

std::string parse_domain_name(const u_char *packet, int offset) {
    /*
        A domain name represented as a sequence of labels, where each label consists of a length
        octet followed by that number of octets
    */
    std::string domain;
    while (true) {
        uint8_t len = packet[offset++]; // first byte is a length of a current string
        if (len == 0) {
            // finish reading
            break;
        }

        if (len & 0xC0) {
            // https://mislove.org/teaching/cs4700/spring11/handouts/project1-primer.pdf
            // chapter 5 DNS Packet Compression
            // 0x3F = 0b00111111, extracting offset from first two bytes
            int pointerOffset = ((len & 0x3F) << 8) | packet[offset++];
            domain += parse_domain_name(packet, pointerOffset);
            break;
        } else {
            domain += std::string((const char *)&packet[offset], len) + '.';
            offset += len;
        }
    }

    return domain;
}

void packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {

    unsigned int offset = 0;

    cout << "Total len: " << header->len << endl;

    // https://github.com/packetzero/dnssniffer/blob/master/src/main.cpp#L166C3-L166C114
    if (header->caplen < header->len) {
        cout <<" Truncated packet: " << header->len << " / " << header->caplen << " bytes" << endl;
    }

    offset += SIZE_ETHERNET_HDR;
    struct ip *iph = (struct ip *)(packet + offset);


    offset += iph->ip_hl * 4;
    struct udphdr *udph = (struct udphdr *)(packet + offset);
    
    offset += sizeof(udph);
    dns_header_t *dnshdr = (dns_header_t *)(packet + offset);

    // build DNS header from acquired data
    DnsHeader dnsheader = DnsHeader(dnshdr, udph, iph, header->ts);
    

    // skip dns header
    offset += sizeof(dnshdr);
    // proceed to parse DNS questions

    for (int i = 0; i < dnsheader.qd_count; i++) {
        // avoiding using structure simmilar to dns header because domain name
        // is a variable and we don't know the exact size of this part of dataframe
        // without parsing domain name

        // WHY DOES IT WORK PERFECTLY WHEN I MANUALLY ADD 4 TO THE OFFSET????
        // i figured it out in wireshark, need to investigate further
        offset += 4;

        std::string domain = parse_domain_name(packet, offset);
        offset += domain.length() + 1; // +1 for null-termination
        
        const char *qtype = parse_dns_question_type(ntohs(*(uint16_t*)(packet + offset)));
        offset += 2; // always 2 bytes for both question type and class 
        
        const char *qclass = parse_dns_question_class(ntohs(*(uint16_t*)(packet + offset)));
        offset += 2;

        std::ostringstream oss;
        oss << domain << " " << qclass << " " << qtype << endl;
        std::string dns_question_record = oss.str();

        dnsheader.questions.push(dns_question_record);
    }

    display_dns_packet(dnsheader, true);


    // dig -p 53 domain.com @8.8.8.8

    // free(question_list->questions);
    // free(question_list);
}


int main(int argc, char* argv[]) {

    // cout << "Byte order: " << (__BYTE_ORDER == __BIG_ENDIAN ? "BIG_ENDIAN" : "LITTLE_ENDIAN") << endl;

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

    // cout << "Applied filter: " << filter << endl;

    pcap_loop(handle, -1, packet_handler, nullptr);

    return 0;
}
