/*
 * Project: DNS Monitor
 *
 * dns-monitor.cpp
 * Created on 21/09/2024
 * 
 * @brief Functions to read network data from a stream (either live interface or PCAP file), 
 *        to process these data and to display it accordingly
 *
 * @author Alina Vinogradova <xvinog00@vutbr.cz>
*/

#include "dns-monitor.hpp"

// Global configurations of the program we will need to access at different points
pcap_t *handle;
parameters_t config;

// Set of unique domain names seen during captured DNS communication
set<string> seenDomainNames;

// Set of unique domain to IPv4/6 translations seen during captured DNS communication
set<string> seenTranslations;

parameters_t get_app_config(int argc, char *argv[]) {
    parameters config = parse(argc, argv);
    return config;
}

string parse_dns_string(const u_char *stream, int *offset, const u_char *DNSstream) {
    string domain;

    while (true) {
        uint8_t len = stream[*offset]; // Get first byte: could be the length of the current label or compression pointer
        (*offset)++;

        if (len == 0) {
            // End of the domain name
            break;
        } else if (len >= 0xC0) {
            // Compression pointer encountered
            //  - The first two bits (11000000 00000000) indicate a pointer
            //  - The remaining 14 (00XXXXXX XXXXXXXX) bits form an offset within the DNS packet
            
            // Get next byte 
            uint8_t nextByte = stream[*offset];
            (*offset)++;

            // Combine the two bytes to get the full 14-bit of offset
            uint16_t bytePair = (len << 8) | nextByte;

            // Mask out the pointer bits (0b00XXXXXXXXXXXXXX)
            int pointerOffset = bytePair & 0x3FFF; 

            // Recursively parse domain name starting at the pointer offset
            domain += parse_dns_string(DNSstream, &pointerOffset, DNSstream);
            
            break; // Pointer is always the last label
        } else { 
            // Standard label
            domain += string((const char *)&stream[*offset], len) + '.'; 
            *offset += len;
        }
    }
    return domain;
}

string process_dns_record(DnsPacket *dnspacket, dns_resource_record_t *record, const u_char *packet, int *offset) {
    string data;
    switch (record->type) {
        case DNS_A: { // IPv4 address
            if (record->rdlength != 4) {
                std::cerr << "Invalid A record length" << std::endl;
                return "ERROROCCURED";
            } else {
                char ipstr[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &record->rdata, ipstr, INET_ADDRSTRLEN);
                data = ipstr;
            }
            *offset += record->rdlength;
            break;
        } case DNS_NS: { // Name server
            data = parse_dns_string(packet, offset, dnspacket->header->DNSstream);
            seenDomainNames.insert(data);
            break;
        } case DNS_CNAME: { // Canonical name
            data = parse_dns_string(packet, offset, dnspacket->header->DNSstream);
            seenDomainNames.insert(data);
            break;
        } case DNS_SOA: { // Start of authority
            string mname = parse_dns_string(packet, offset, dnspacket->header->DNSstream);
            seenDomainNames.insert(mname);

            // https://www.cloudflare.com/learning/dns/dns-records/dns-soa-record/

            // rname represents the administrator's email address,
            // so we don't want to save it in seen domain names
            string rname = parse_dns_string(packet, offset, dnspacket->header->DNSstream);

            dns_soa_record_t *soa = (dns_soa_record_t *)malloc(sizeof(dns_soa_record_t));
            if (soa == NULL) {
                std::cerr << "Malloc failed: answers_handler soa" << std::endl;
                free(record);
                return "ERROROCCURED"; // Handle allocation failure
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
            uint16_t preference;
            memcpy(&preference, &packet[*offset], 2);

            *offset += 2;
            preference = ntohs(preference);
            // https://www.cloudflare.com/learning/dns/dns-records/dns-mx-record/
            // The same as in SOA record, this string is a mail server, so we want to display it,
            // But we don't want to save it in domain names 
            string mail = parse_dns_string(packet, offset, dnspacket->header->DNSstream);
            data = to_string(preference) + " " + mail;
                
            break;
        } case DNS_AAAA: { // IPv6 address
            if (record->rdlength != 16) {
                std::cerr << "Invalid AAAA record length" << std::endl;
                return "ERROROCCURED";
            } else {
                char ip6str[INET6_ADDRSTRLEN];
                inet_ntop(AF_INET6, &record->rdata, ip6str, INET6_ADDRSTRLEN);
                data = ip6str;
            }
            *offset += record->rdlength;
            break;
        } case DNS_SRV: {
            dns_srv_record_t *srv = (dns_srv_record_t *)malloc(sizeof(dns_srv_record_t));
            if (srv == NULL) {
                std::cerr << "Malloc failed: answers_handler srv" << std::endl;
                free(record);
                return "ERROROCCURED"; // Handle allocation failure
            }

            memcpy(&srv->priority, &packet[*offset], 2); *offset += 2;
            srv->priority = ntohs(srv->priority);

            memcpy(&srv->weight, &packet[*offset], 2); *offset += 2;
            srv->weight = ntohs(srv->weight);

            memcpy(&srv->port, &packet[*offset], 2); *offset += 2;
            srv->port = ntohs(srv->port);

            string target = parse_dns_string(packet, offset, dnspacket->header->DNSstream);
            seenDomainNames.insert(target);

            data = to_string(srv->priority) + " " + to_string(srv->weight) + " " + 
                   to_string(srv->port) + " " + target;

            free(srv);
            break;
        } default: {
            // Unsupported answer type, skip it
            *offset += record->rdlength;
            free(record);
            return "CONTINUE";
        }
    }
    return data;
}

void questions_handler(DnsPacket *dnspacket, const u_char *packet, int *offset) {
    for (int i = 0; i < dnspacket->header->qd_count; i++) {
        // avoiding using structure simmilar to dns header because domain name
        // has variable size and we don't know the exact size of this part of dataframe
        // without parsing domain name

        // WHY DOES IT WORK PERFECTLY WHEN I MANUALLY ADD 4 TO THE OFFSET????
        // i figured it out in wireshark, need to investigate further
        *offset += 4;

        string domain = parse_dns_string(packet, offset, dnspacket->header->DNSstream);
        seenDomainNames.insert(domain);
        
        // Extract question type
        const char *qtype = PARSE_DNS_TYPE(ntohs(*(uint16_t*)(packet + *offset)));
        *offset += 2; // always 2 bytes for both question type and class 

        if (!strcmp(qtype, "UNKNWN")) {
            // dnspacket->questions.push_back("Record type not supported\n");
            *offset += 2;
            continue;
        }
        
        const char *qclass = PARSE_DNS_CLASS(ntohs(*(uint16_t*)(packet + *offset)));
        *offset += 2;

        ostringstream oss;
        oss << domain << " " << qclass << " " << qtype << endl;
        string dnsquestion = oss.str();

        dnspacket->questions.push_back(dnsquestion);
    }
}

dns_resource_record_t *extract_record(const u_char *packet, int *offset) {
    dns_resource_record_t *record = (dns_resource_record_t *)malloc(sizeof(dns_resource_record_t));
    if (record == NULL) {
        cerr << "Malloc failed for dns_resource_record" << endl;
        return NULL;
    }

    // Extract record type
    memcpy(&record->type, &packet[*offset], 2);
    record->type = ntohs(record->type);
    *offset += 2;

    // Extract record class
    memcpy(&record->class_, &packet[*offset], 2);
    record->class_ = ntohs(record->class_);
    *offset += 2;

    // Extract record TTL
    memcpy(&record->ttl, &packet[*offset], 4);
    record->ttl = ntohl(record->ttl);
    *offset += 4;

    // Extract record data length
    memcpy(&record->rdlength, &packet[*offset], 2);
    record->rdlength = ntohs(record->rdlength);
    *offset += 2;

    size_t resizeRecord = sizeof(dns_resource_record_t) - sizeof(record->rdata) + record->rdlength;
    record = (dns_resource_record_t *)realloc(record, resizeRecord);

    if (record == NULL) {
        cerr << "Realloc failed for dns_resource_record" << endl;
    }

    // Extract record data
    memcpy(&record->rdata, &packet[*offset], record->rdlength); 

    return record;
}

int process_sections(int mode, DnsPacket *dnspacket, const u_char *packet, int *offset) {
    int n;
    vector<string>* storageStream;

    if (mode == MODE_ANSWERS) {
        storageStream = &dnspacket->answers;
        n = dnspacket->header->an_count;
    } else if (mode == MODE_AUTHORITY) {
        storageStream = &dnspacket->authorities;
        n = dnspacket->header->ns_count;
    } else if (mode == MODE_ADDITIONAL) {
        storageStream = &dnspacket->additionals;
        n = dnspacket->header->ar_count;
    }
    
    for (int i = 0; i < n; i++) {
        // Parse domain name
        string domain_name = parse_dns_string(packet, offset, dnspacket->header->DNSstream);

        // Parse record data (type, class, ttl, data length, data)
        dns_resource_record_t *record = extract_record(packet, offset);
        if (record == NULL) return RET_ERR;

        // Handle different answer types
        string data = process_dns_record(dnspacket, record, packet, offset);

        if (!data.compare("CONTINUE")) {
            // storageStream->push_back("Record type not supported\n");
            continue;
        }

        if (!data.compare("ERROROCCURED")) {
            return RET_ERR;
        }

        // Only saving a domain, if the record type is supported by a program
        seenDomainNames.insert(domain_name);

        if (record->type == DNS_A || record->type == DNS_AAAA) {
            string translation = domain_name + " " + data;
            seenTranslations.insert(translation);
        }

        // Prepare to store the formatted answer string
        ostringstream ans;

        // Format the answer string and add it to the packet's answer list
        ans << domain_name << " " << record->ttl << " " << PARSE_DNS_CLASS(record->class_) << " " << PARSE_DNS_TYPE(record->type) << " " << data << endl;
        
        // Store record data to DNS packet
        storageStream->push_back(ans.str());

        // Free the answer structure
        free(record);
    }

    return RET_OK;
}

set<string> load_file(const string& filename) {
    set<string> output;

    if (!filename.empty()) {
        ifstream inputFile(filename);
        string line;
        if (inputFile.is_open()) {
            while (getline(inputFile, line)) {
                output.insert(line);
            }
            inputFile.close();
        }
    }

    return output;
}

void update_data_files(const string& filename, const set<string>& seenData) {
    if (!filename.empty()) {
        set<string> savedData = load_file(filename);

        if (savedData != seenData) {
            ofstream outputFile;
            outputFile.open(filename, ios::app);
            // ofstream outputFile(filename);

            if (outputFile.is_open()) {
                for (const string& item : seenData) {
                    if (savedData.find(item) == savedData.end()) {
                        outputFile << item << endl;
                    }
                }
                outputFile.close();
            }
        }
    }
}

void packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {

    int offset = 0;

    // cout << "Total len: " << header->len << endl;

    // https://github.com/packetzero/dnssniffer/blob/master/src/main.cpp#L166C3-L166C114
    if (header->caplen < header->len) {
        cout <<" Truncated packet: " << header->len << " / " << header->caplen << " bytes" << endl;
    }

    // https://github.com/jsemaljaa/ipk22-projects/blob/main/Proj2/ipk-sniffer.c
    struct ether_header *etherhdr = (struct ether_header *)packet;
    uint16_t etherType = ntohs(etherhdr->ether_type);

    struct ip *iphdr;
    struct ip6_hdr *ip6hdr;

    bool ipv6 = false;

    const int ethhdrSize = sizeof(struct ether_header);

    offset += ethhdrSize;

    switch (etherType) {
        case ETHERTYPE_ARP:
            // no need any data, skip
            // offset += ethhdrSize;
            break;
        case ETHERTYPE_IP:
            iphdr = (struct ip *)(packet + offset);
            // IPv4 doesn't have a fixed header length, minimum 20 bytes and maximum 60 bytes
            // ipvhdrLen = iphdr->ip_hl * 4;
            offset += iphdr->ip_hl * 4;
            break;
        case ETHERTYPE_IPV6: 
            ip6hdr = (struct ip6_hdr *)(packet + offset);
            ipv6 = true;
            // IPv6 has 40 bytes as fixed header length
            // ipvhdrLen = 40;
            offset += 40;
            break;
    }

    // offset += iph->ip_hl * 4;
    struct udphdr *udph = (struct udphdr *)(packet + offset);
    
    offset += sizeof(udph);
    dns_header_t *dnshdr = (dns_header_t *)(packet + offset);

    // Build DNS header from acquired data
    DnsHeader dnsheader = DnsHeader(dnshdr, udph, iphdr, ip6hdr, ipv6, header->ts);
    dnsheader.DNSstream = &packet[offset];

    DnsPacket *dnspacket = new DnsPacket();
    dnspacket->header = &dnsheader;

    offset += sizeof(dnshdr);


    // cout << "Offset before questions handler: " << offset << endl;
    // cout << "Starting to process packet 0x" << hex << setw(4) << setfill('0') << dnspacket->header->id << dec << " with source port: " << dnspacket->header->src_port << endl; 

    if (!config.verbose) {
        display_dns_packet_short(*dnspacket);
        return;
    }

    // Proceed to parse DNS records (questions, answers, etc.)
    questions_handler(dnspacket, packet, &offset);
    EXEC(process_sections(MODE_ANSWERS, dnspacket, packet, &offset));
    EXEC(process_sections(MODE_AUTHORITY, dnspacket, packet, &offset));
    EXEC(process_sections(MODE_ADDITIONAL, dnspacket, packet, &offset));

    display_dns_packet_verbose(*dnspacket);

    if (!config.domainsfile.empty()) {
        update_data_files(config.domainsfile, seenDomainNames);
    }

    if (!config.translationsfile.empty()) {
        update_data_files(config.translationsfile, seenTranslations);
    }

    delete dnspacket;
}

void signal_handler(int signum) {
    pcap_breakloop(handle); 
}

int main(int argc, char* argv[]) {

    // cout << "Byte order: " << (__BYTE_ORDER == __BIG_ENDIAN ? "BIG_ENDIAN" : "LITTLE_ENDIAN") << endl;
    config = get_app_config(argc, argv);

    handle = nullptr;
    char errbuf[PCAP_ERRBUF_SIZE];    

    // Preparing PCAP handle
    /* PCAP FILTER */
    char filter[] = "udp port 53";
    struct bpf_program fp;
    bpf_u_int32 net = 0;

    if (!config.interface.empty()) {
        handle = pcap_open_live(config.interface.c_str(), BUFSIZ, 1, 1000, errbuf);
        pcap_geterr(handle);
    } else if (!config.pcapfile.empty()) {
        handle = pcap_open_offline(config.pcapfile.c_str(), errbuf);
        pcap_geterr(handle);
    } else {
        // Technically not possible, but to avoid unexpected behaviour
        cerr << "Error: You must specify either an interface (-i) or a PCAP file (-p). (but not both)\n";
        exit(EXIT_FAILURE);
    }

    if (handle == nullptr) {
        fprintf(stderr, "Something went wrong: %s\n", errbuf);
        exit(EXIT_FAILURE);
    }

    if (pcap_compile(handle, &fp, filter, 0, net) == -1) {
        fprintf(stderr, "Error compiling filter: %s\n", pcap_geterr(handle));
        exit(EXIT_FAILURE);
    }

    if (pcap_setfilter(handle, &fp) == -1) {
	    fprintf(stderr, "Error setting filter: %s\n", pcap_geterr(handle));
        exit(EXIT_FAILURE);
    }

    if (!config.interface.empty()) {
        pcap_loop(handle, -1, packet_handler, nullptr);
    } else {
        struct pcap_pkthdr header;
        const u_char *packet;
        while ((packet = pcap_next(handle, &header)) != nullptr) {
            packet_handler(nullptr, &header, packet);
        }
    }

    // Register the signal handler
    signal(SIGINT, signal_handler);

    // Cleaning up after receiving SIGINT signal
    // Free the compiled filter
    pcap_freecode(&fp); 
    pcap_close(handle);

    return 0;
}
