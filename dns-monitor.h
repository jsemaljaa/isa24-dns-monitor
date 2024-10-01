//
// Created by Alina Vinogradova on 9/21/2024.
//

#ifndef DNS_MONITOR_H
#define DNS_MONITOR_H

#include <cstdint>
#include <pcap.h>
#include <fstream>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <string.h>
#include <vector>

#include "parameters.h"

struct dns_header {
    uint16_t id;       // identification number
    uint16_t flags;    // DNS flags
    uint16_t qd_count; // number of question entries
    uint16_t an_count; // number of answer entries
    uint16_t ns_count; // number of authority entries
    uint16_t ar_count; // number of resource entries
};

#endif //DNS_MONITOR_H
