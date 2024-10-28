//
// Created by Alina Vinogradova on 9/21/2024.
//

#include "dns-monitor.h"

using namespace std;

// g++ -o dns-monitor dns-monitor.cpp -lpcap
// dig -p 53 domain.com @8.8.8.8


void debug_display_offset(int *offset) {
    cout << "[DEBUG] Current offset: " << *offset << endl;
}

// https://en.wikipedia.org/wiki/List_of_DNS_record_types
const char *parse_dns_type(uint16_t type) {
    switch (type) {
    case DNS_A:
        return "A";
    case DNS_NS:
        return "NS";
    case DNS_CNAME:
        return "CNAME";
    case DNS_SOA:
        return "SOA";
    case DNS_MX:
        return "MX";
    case DNS_AAAA:
        return "AAAA";
    case DNS_SRV:
        return "SRV";
    default:
        return "UNKNWN";
    }
}

const char *parse_dns_class(uint16_t qclass) {
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

void display_dns_packet(dns_header *dnsh) {

    // for (int i = 0; i < dnsh->qd_count; i++) {
        // struct dns_question *dnsq = (struct dns_question *)(dnsh + )
    // }

        // google.com. IN A
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

string parse_domain_name(const u_char *packet, int *offset) {
    /*
        A domain name represented as a sequence of labels, where each label consists of a length
        octet followed by that number of octets
    */
    
    string domain;

    while (true) {
        uint8_t len = packet[*offset]; // first byte is a length of a current string
        cout << "Got byte: " << hex << setfill('0') << setw(2) << static_cast<int>(len) << dec << endl;
        // cout << "Got byte: " << static_cast<int>(len) << endl;
        (*offset)++;

        if (len == 0) {
            // finish reading
            break;
        } else if (len & 0xC0) {
            // https://mislove.org/teaching/cs4700/spring11/handouts/project1-primer.pdf
            // chapter 5 DNS Packet Compression
            // 0x3F = 0b00111111, extracting offset from first two bytes
            
            int pointerOffset = ((len & 0x3F) << 8) | packet[*offset];
            (*offset)++;

            pointerOffset = ntohs(pointerOffset);

            domain += parse_domain_name(packet, &pointerOffset);

            break;
        } else {
            domain += string((const char *)&packet[*offset], len) + '.';
            *offset += len;
        }
    }

    return domain;
}

string serve_dns_answer(dns_record_t record) {
    // constructing a string to display
    // google.com. 300 IN A 142.250.183.142
    // [name] [TTL] [class] [type] [data]

    ostringstream oss;
    // oss << domain << " " << qclass << " " << qtype << endl;
    // string dns_question_record = oss.str();

    string data;

    cout << "[serve dns answer] record type: " << record.type << endl;

    if (record.type == DNS_A) {
        // extracting IPv4 address
        char ipstr[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, record.rdata, ipstr, INET_ADDRSTRLEN);
        data.resize(INET_ADDRSTRLEN);
        cout << "DNS ANSWER TYPE A IP: " << ipstr << endl;
        copy(ipstr, ipstr + INET_ADDRSTRLEN, data.begin());
    } else if (record.type == DNS_NS || record.type == DNS_CNAME) {
        data = parse_domain_name(record.rdata, 0);
    } else if (record.type == DNS_SOA) {

    } else if (record.type == DNS_MX) {
        int offset = 0;
        uint16_t p = ntohs(*(uint16_t*)(record.rdata + offset)); offset += 2;
        data = parse_domain_name(record.rdata, &offset);
    } else if (record.type == DNS_AAAA) {
        char ip6str[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, record.rdata, ip6str, INET6_ADDRSTRLEN);
        data.resize(INET6_ADDRSTRLEN);
        copy(ip6str, ip6str + INET6_ADDRSTRLEN, data.begin());
    } else {
        // return "";
    }

    oss << record.name << " " << record.ttl << " " << record.class_ << " " << record.type << " " << data << endl;
    cout << "[DEBUG] Returning: " << oss.str();
    return oss.str();
}

void display_dns_packet(DnsPacket dnspacket, bool verbose) {

    if (verbose) {
        cout << "Timestamp: " << dnspacket.header->timestamp << endl;
        cout << "SrcIP: " << dnspacket.header->src_ip << endl;
        cout << "DstIP: " << dnspacket.header->dst_ip << endl;
        cout << "SrcPort: UDP/" << dnspacket.header->src_port << endl;
        cout << "DstPort: UDP/" << dnspacket.header->dst_port << endl;
        // cout << "Identifier: " << hex << uppercase << "0x" << ntohs(dnsh->id) << endl;
        cout << "Identifier: " << dnspacket.header->id << endl;
        cout << "Flags: ";
            cout << "QR=" << dnspacket.header->get_qr() << ", ";
            cout << "OPCODE=" << dnspacket.header->get_opcode() << ", ";
            cout << "AA=" << dnspacket.header->get_aa() << ", ";
            cout << "TC=" << dnspacket.header->get_tc() << ", ";
            cout << "RD=" << dnspacket.header->get_rd() << ", ";
            cout << "RA=" << dnspacket.header->get_ra() << ", ";
            cout << "AD=" << dnspacket.header->get_ad() << ", ";
            cout << "CD=" << dnspacket.header->get_cd() << ", ";
            cout << "RCODE=" << dnspacket.header->get_rcode() << endl;
        
        cout << endl; 

        if (!dnspacket.questions.empty()) {
            cout << "[Question Section]" << endl;
            
            for (const std::string& q : dnspacket.questions) {
                if (!q.empty()) cout << q;
            }
            
            cout << endl;
        }

        if (!dnspacket.answers.empty()) {
            cout << "[Answer Section]" << endl;
            // google.com. 300 IN A 142.250.183.142
            // [name] [TTL] [class] [type] [data]

            for (const string &a : dnspacket.answers) {
                if (!a.empty()) cout << a;
            }
            
            cout << endl;
        }
        
        cout << "====================" << endl;
    } else {
        cout << dnspacket.header->timestamp << " ";
        cout << dnspacket.header->src_ip << " -> " << dnspacket.header->dst_ip << " ";
        cout << "(" << ((dnspacket.header->get_qr() == 1) ? "R" : "Q") << " ";
        cout << dnspacket.header->qd_count << "/";
        cout << dnspacket.header->an_count << "/";
        cout << dnspacket.header->ns_count << "/";
        cout << dnspacket.header->ar_count << ")" << endl;
    }
}

void answers_handler(DnsPacket *dnspacket, const u_char *packet, int *offset) {
    for (int i = 0; i < dnspacket->header->an_count; i++) {

        dns_record_t answer;
        answer.name = parse_domain_name(packet, offset);
        cout << "[After answer.name] "; debug_display_offset(offset);
        cout << "Domain name " << answer.name << endl;

        // answer.type = (uint16_t)(packet + offset);
        answer.type = ntohs(*(uint16_t *)packet + *offset); 
        *offset += 2;
        cout << "[After answer.type] "; debug_display_offset(offset);
        cout << "Answer type " << answer.type << endl;

        // answer.class_ = (uint16_t)(packet + offset);
        answer.class_ = ntohs(*(uint16_t *)packet + *offset); 
        *offset += 2;
        cout << "[After answer.class] "; debug_display_offset(offset);
        cout << "Answer class " << answer.class_ << endl;

        // answer.ttl = (uint32_t)(packet + offset);
        answer.ttl = ntohl(*(uint16_t *)packet + *offset); 
        *offset += 4;
        cout << "[After answer.ttl] "; debug_display_offset(offset);
        cout << "Answer ttl " << answer.ttl << endl;

        // answer.rdlength = (uint16_t)(packet + offset);
        answer.rdlength = ntohs(*(uint16_t *)packet + *offset); 
        *offset += 2;
        cout << "[After answer.rdlength] "; debug_display_offset(offset);
        cout << "Answer rdl " << answer.rdlength << endl;

        answer.rdata = (unsigned char *)(packet + *offset); 
        cout << "[After answer.rdata] "; debug_display_offset(offset);
        cout << "Answer rdata " << answer.rdata << endl;

        cout << answer.name << " " << answer.type << " " << answer.class_ << " " << answer.ttl << " " << answer.rdlength << " " << answer.rdata << endl << endl;

        // length of data + 10 fixed bytes
        // *offset += answer.rdlength + 10;
        
        debug_display_offset(offset);

        ostringstream ans;
        string data;

        if (answer.type == DNS_A) {
            // extracting IPv4 address
            char ipstr[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, answer.rdata, ipstr, INET_ADDRSTRLEN);
            data.resize(INET_ADDRSTRLEN);
            cout << "DNS ANSWER TYPE A IP: " << ipstr << endl;
            copy(ipstr, ipstr + INET_ADDRSTRLEN, data.begin());
        } else if (answer.type == DNS_NS || answer.type == DNS_CNAME) {
            data = parse_domain_name(answer.rdata, 0);
        } else if (answer.type == DNS_SOA) {

        } else if (answer.type == DNS_MX) {
            int offset = 0;
            uint16_t p = ntohs(*(uint16_t*)(answer.rdata + offset)); offset += 2;
            data = parse_domain_name(answer.rdata, &offset);
        } else if (answer.type == DNS_AAAA) {
            char ip6str[INET6_ADDRSTRLEN];
            inet_ntop(AF_INET6, answer.rdata, ip6str, INET6_ADDRSTRLEN);
            data.resize(INET6_ADDRSTRLEN);
            copy(ip6str, ip6str + INET6_ADDRSTRLEN, data.begin());
        } else {
            // continue;
        }

        ans << answer.name << " " << answer.ttl << " " << answer.class_ << " " << answer.type << " " << data << endl;

        // dnspacket->answers.push_back(serve_dns_answer(answer));
        dnspacket->answers.push_back(ans.str());
    }
}

void questions_handler(DnsPacket *dnspacket, const u_char *packet, int *offset) {
    for (int i = 0; i < dnspacket->header->qd_count; i++) {
        // avoiding using structure simmilar to dns header because domain name
        // has variable size and we don't know the exact size of this part of dataframe
        // without parsing domain name

        // WHY DOES IT WORK PERFECTLY WHEN I MANUALLY ADD 4 TO THE OFFSET????
        // i figured it out in wireshark, need to investigate further
        *offset += 4;

        string domain = parse_domain_name(packet, offset);
        
        const char *qtype = parse_dns_type(ntohs(*(uint16_t*)(packet + *offset)));
        *offset += 2; // always 2 bytes for both question type and class 
        
        const char *qclass = parse_dns_class(ntohs(*(uint16_t*)(packet + *offset)));
        *offset += 2;

        ostringstream oss;
        oss << domain << " " << qclass << " " << qtype << endl;
        string dnsquestion = oss.str();

        dnspacket->questions.push_back(dnsquestion);
    }
}

void packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {

    int offset = 0;

    // cout << "Total len: " << header->len << endl;

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
    
    DnsPacket *dnspacket = new DnsPacket();
    dnspacket->header = &dnsheader;

    offset += sizeof(dnshdr);

    // proceed to parse DNS records (questions, answer, etc.)

    questions_handler(dnspacket, packet, &offset);
    debug_display_offset(&offset);
    answers_handler(dnspacket, packet, &offset);

    display_dns_packet(*dnspacket, true);

    delete dnspacket;
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
