/*
 * Project: DNS Monitor
 *
 * dns-monitor.hpp
 * Created on 21/09/2024
 * 
 * @brief Declarations of values and functions needed for data extraction
 *
 * @author Alina Vinogradova <xvinog00@vutbr.cz>
*/

#ifndef DNS_MONITOR_H
#define DNS_MONITOR_H

// Networking
#include <pcap.h>
#include <netinet/ip6.h>
// ethernet header
#include <netinet/if_ether.h>

#include <cstring>
#include <fstream>
#include <csignal>

// Project headers
// #include "parameters.hpp"
#include "display-packet.hpp"

#define RET_OK 0
#define RET_ERR 1

// https://en.wikipedia.org/wiki/List_of_DNS_record_types
#define PARSE_DNS_TYPE(type)            \
    ((type) == DNS_A ? "A" :            \
    (type) == DNS_NS ? "NS" :           \
    (type) == DNS_CNAME ? "CNAME" :     \
    (type) == DNS_SOA ? "SOA" :         \
    (type) == DNS_MX ? "MX" :           \
    (type) == DNS_AAAA ? "AAAA" :       \
    (type) == DNS_SRV ? "SRV" :         \
    "UNKNWN")

#define PARSE_DNS_CLASS(qclass)         \
    ((qclass) == 1 ? "IN" : "UNKNWN") 

#define EXEC(func)                      \
    do {                                \
        int code = (func);              \
        if (code != RET_OK) exit(code); \
    } while(0)                          \

#define MODE_ANSWERS 0
#define MODE_AUTHORITY 1
#define MODE_ADDITIONAL 2

using namespace std;

parameters get_app_config(int argc, char* argv[]);
/*
        Parses a domain name from a DNS packet stream.

        Domain names are represented as a sequence of labels, where each label consists of:
            - A length octet specifying the number of characters in the label.
            - The characters of the label.

        This function handles both standard labels and compressed labels (using pointers).

        Sources:
            - https://mislove.org/teaching/cs4700/spring11/handouts/project1-primer.pdf
              chapter 5 DNS Packet Compression 
            - https://spathis.medium.com/how-dns-got-its-messages-on-diet-c49568b234a2

*/
/* @brief Parse a domain name from a DNS packet stream
 * 
 * 
 */
string parse_dns_string(const u_char *stream, int *offset, const u_char *DNSstream);
string process_dns_record(DnsPacket *dnspacket, dns_resource_record_t *record, const u_char *packet, int *offset);
void questions_handler(DnsPacket *dnspacket, const u_char *packet, int *offset);
dns_resource_record_t *extract_record(const u_char *packet, int *offset);
int process_sections(int mode, DnsPacket *dnspacket, const u_char *packet, int *offset);
set<string> load_file(const string& filename);
void update_data_files(const string& filename, const set<string>& seenData);
void packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);
void signal_handler(int signum);

#endif //DNS_MONITOR_H
