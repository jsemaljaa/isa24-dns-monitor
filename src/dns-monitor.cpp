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

string parse_domain_name(const u_char *stream, int *offset, const u_char *DNSstream) {
    /*
        A domain name represented as a sequence of labels, where each label consists of a length
        octet followed by that number of octets
    */

    string domain;

    while (true) {
        uint8_t len = stream[*offset]; // first byte is a length of a current string

        // cout << "Got byte: " << hex << setfill('0') << setw(2) << static_cast<int>(len) << dec << endl;

        (*offset)++;

        // uint8_t firstByte = (len >> 8) & 0xFF;
        // uint8_t secondByte = len & 0xFF;

        if (len == 0) {
            // finish reading
            break;
        } else if (len >= 0xC0) {
            // https://mislove.org/teaching/cs4700/spring11/handouts/project1-primer.pdf
            // chapter 5 DNS Packet Compression

            // first two bits indicates that this is a compression pointer
            // the rest 14 bits are an actual pointer 
            // int pointerOffset = ((len & 0x3F) << 8) | packet[*offset];
            
            // read next byte 
            uint8_t nextByte = stream[*offset];
            (*offset)++;

            uint16_t bytePair = (len << 8) | nextByte;

            int pointerOffset = bytePair & 0x3FFF;

            // if we got a compression pointer and extracted the place where it points to
            // then we're starting to parse domain name from the beginning of DNS packet stream with given pointer offset

            domain += parse_domain_name(DNSstream, &pointerOffset, DNSstream);
            
            break;
        } else {
            domain += string((const char *)&stream[*offset], len) + '.';
            *offset += len;
        }
    }

    return domain;
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

        if (!(dnspacket.questions.empty() && dnspacket.header->qd_count == 0)) {
            cout << "[Question Section]" << endl;
            
            for (const std::string& q : dnspacket.questions) {
                if (!q.empty()) cout << q;
            }
            
            cout << endl;
        }

        if (!(dnspacket.answers.empty() && dnspacket.header->an_count == 0)) {
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
    // Iterate through each answer in the DNS packet
    for (int i = 0; i < dnspacket->header->an_count; i++) {
        // Parse the domain name
        string domain_name = parse_domain_name(packet, offset, dnspacket->header->DNSstream);

        // Allocate memory for the answer structure
        dns_answer_t *answer = (dns_answer_t *)malloc(sizeof(dns_answer_t));
        if (answer == NULL) {
            std::cerr << "Malloc failed: answers_handler" << std::endl;
            return; // Handle allocation failure appropriately
        }

        // Extract answer type
        memcpy(&answer->type, &packet[*offset], 2);
        answer->type = ntohs(answer->type);
        *offset += 2;

        // Extract answer class
        memcpy(&answer->class_, &packet[*offset], 2);
        answer->class_ = ntohs(answer->class_);
        *offset += 2;

        // Extract answer TTL
        memcpy(&answer->ttl, &packet[*offset], 4);
        answer->ttl = ntohl(answer->ttl);
        *offset += 4;

        // Extract answer data length
        memcpy(&answer->rdlength, &packet[*offset], 2);
        answer->rdlength = ntohs(answer->rdlength);
        *offset += 2;

        // Extract answer data
        memcpy(&answer->rdata, &packet[*offset], answer->rdlength);

        // Prepare to store the formatted answer string
        ostringstream ans;
        string data;

        // Handle different answer types
        switch (answer->type) {
            case DNS_A: { // IPv4 address
                if (answer->rdlength != 4) {
                    std::cerr << "Invalid A record length" << std::endl;
                } else {
                    char ipstr[INET_ADDRSTRLEN];
                    inet_ntop(AF_INET, &answer->rdata, ipstr, INET_ADDRSTRLEN);
                    data = ipstr;
                }
                *offset += answer->rdlength;
                break;
            } case DNS_NS: { // Name server
                data = parse_domain_name(packet, offset, dnspacket->header->DNSstream);
                break;
            } case DNS_CNAME: { // Canonical name
                data = parse_domain_name(packet, offset, dnspacket->header->DNSstream);
                break;
            } case DNS_SOA: { // Start of authority
                string mname = parse_domain_name(packet, offset, dnspacket->header->DNSstream);
                string rname = parse_domain_name(packet, offset, dnspacket->header->DNSstream);

                dns_soa_record_t *soa = (dns_soa_record_t *)malloc(sizeof(dns_soa_record_t));
                if (soa == NULL) {
                    std::cerr << "Malloc failed: answers_handler soa" << std::endl;
                    free(answer);
                    return; // Handle allocation failure
                }

                memcpy(&soa->serial, &packet[*offset], 4); *offset += 4; 
                soa->serial = ntohl(soa->serial);
        
                memcpy(&soa->refresh, &packet[*offset], 4); *offset += 4;
                soa->refresh = ntohl(soa->refresh);

                memcpy(&soa->retry, &packet[*offset], 4); *offset += 4;
                soa->retry = ntohl(soa->retry);

                memcpy(&soa->expire, &packet[*offset], 4); *offset += 4;
                soa->expire = ntohl(soa->expire);

                memcpy(&soa->minimum, &packet[*offset], 4); *offset += 4;
                soa->minimum = ntohl(soa->minimum);

                data = mname + " " + rname + " " + 
                       to_string(soa->serial) + " " + to_string(soa->refresh) + " " + 
                       to_string(soa->retry) + " " + to_string(soa->expire) + " " + to_string(soa->minimum);
        
                free(soa);
                break;
            } case DNS_MX: { // Mail exchange
                int localOffset = 0;
                uint16_t preference;
                memcpy(&preference, &answer->rdata + localOffset, 2);
                localOffset += 2;
                preference = ntohs(preference);

                const u_char *mxStream = (const u_char *)answer->rdata + localOffset;

                string mail = parse_domain_name(mxStream, &localOffset, dnspacket->header->DNSstream);
                data = to_string(preference) + " " + mail;
                break;
            } case DNS_AAAA: { // IPv6 address
                if (answer->rdlength != 16) {
                std::cerr << "Invalid AAAA record length" << std::endl;
                } else {
                    char ip6str[INET6_ADDRSTRLEN];
                    inet_ntop(AF_INET6, &answer->rdata, ip6str, INET6_ADDRSTRLEN);
                    data = ip6str;
                }
                *offset += answer->rdlength;
                break;
            } default: {
                // Unsupported answer type, skip it
                free(answer);
                *offset += answer->rdlength;
                continue;
            }
        }

        // Format the answer string and add it to the packet's answer list
        ans << domain_name << " " << answer->ttl << " " << parse_dns_class(answer->class_) << " " << parse_dns_type(answer->type) << " " << data << endl;
        
        dnspacket->answers.push_back(ans.str());

        // Free the answer structure
        free(answer);
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

        string domain = parse_domain_name(packet, offset, dnspacket->header->DNSstream);
        
        const char *qtype = parse_dns_type(ntohs(*(uint16_t*)(packet + *offset)));
        *offset += 2; // always 2 bytes for both question type and class 

        if (!strcmp(qtype, "UNKNWN")) continue;
        
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
    dnsheader.DNSstream = &packet[offset];

    DnsPacket *dnspacket = new DnsPacket();
    dnspacket->header = &dnsheader;

    offset += sizeof(dnshdr);

    // proceed to parse DNS records (questions, answer, etc.)

    // when we are passing a packet
    // we want to restrict it to the beginning of dns message
    // (after dns header)
    // int messageOffset = 0;

    questions_handler(dnspacket, packet, &offset);
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
