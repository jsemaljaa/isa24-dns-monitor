//
// Created by Alina Vinogradova on 9/21/2024.
//

#ifndef DNS_MONITOR_H
#define DNS_MONITOR_H


// Networking
#include <pcap.h>
#include <netinet/udp.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>

#include <cstring>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <ctime>

#include <string>

// Project headers
#include "parameters.h"
#include "dns_packet.h"

#define SIZE_ETHERNET_HDR 14
#define MIN_DNS_HDR_SIZE 12

parameters get_app_config(int argc, char* argv[]);
void packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);

#endif //DNS_MONITOR_H
