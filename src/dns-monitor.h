//
// Created by Alina Vinogradova on 9/21/2024.
//

#ifndef DNS_MONITOR_H
#define DNS_MONITOR_H

#include <cstdint>
// Networking
#include <pcap.h>
#include <netinet/ip6.h>
#include <netinet/if_ether.h>

#include <cstring>
#include <fstream>
#include <iostream>


// Project headers
#include "parameters.h"
#include "dns_packet.h"

#define SIZE_ETHERNET_HDR 14
#define MIN_DNS_HDR_SIZE 12

#define RET_OK 0
#define RET_ERR 1

parameters get_app_config(int argc, char* argv[]);
void packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);

#endif //DNS_MONITOR_H
