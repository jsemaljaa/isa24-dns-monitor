//
// Created by Alina Vinogradova on 9/21/2024.
//

#ifndef DNS_MONITOR_H
#define DNS_MONITOR_H



#include <iostream>
#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <cstring>
#include <fstream>

#include <string>
#include <cstdint>
#include "parameters.h"

#define ETHER_ADDR_LEN	6
#define SIZE_ETHERNET_HDR 14
#define MIN_DNS_HDR_SIZE 12

struct dns_header {
    uint16_t id;       // identification number
    uint16_t flags;    // DNS flags
    uint16_t qd_count; // number of question entries
    uint16_t an_count; // number of answer entries
    uint16_t ns_count; // number of authority entries
    uint16_t ar_count; // number of additional entries
};

parameters get_app_config(int argc, char* argv[]);
void packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);

#endif //DNS_MONITOR_H
