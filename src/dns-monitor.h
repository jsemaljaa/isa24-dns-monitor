//
// Created by Alina Vinogradova on 9/21/2024.
//

#ifndef DNS_MONITOR_H
#define DNS_MONITOR_H



#include <iostream>
#include <pcap.h>
// #include <netinet/ip.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <cstring>
#include <fstream>
#include <iomanip>
#include <ctime>

#include <string>
#include <cstdint>
#include "parameters.h"

#define SIZE_ETHERNET_HDR 14
#define MIN_DNS_HDR_SIZE 12

// https://mislove.org/teaching/cs4700/spring11/handouts/project1-primer.pdf 
// https://www.catchpoint.com/blog/how-dns-works

// changed the structure according to this: 
// https://stackoverflow.com/questions/59594815/dns-query-format-little-big-endian-problem-in-header-structure
struct dns_header {
    uint16_t id;       // identification number
#if __BYTE_ORDER == __BIG_ENDIAN
	uint16_t RD:1;     // recursion desired
	uint16_t TC:1; 	   // truncated message
	uint16_t AA:1;	   // authoritative answer
	uint16_t opcode:4; // purpose of message
	uint16_t qr:1;	   // query/response flag
	uint16_t rcode:4;  // response code
	uint16_t CD:1;	   // checking disabled
	uint16_t AD:1;	   // authenticated data
	uint16_t Z:1;	   // reserved for future
	uint16_t RA:1;     // recursion available
#elif __BYTE_ORDER == __LITTLE_ENDIAN
	uint16_t qr:1;     // recursion desired
	uint16_t opcode:4; // purpose of message
	uint16_t AA:1;	   // authoritative answer
	uint16_t TC:1; 	   // truncated message
	uint16_t RD:1;     // recursion desired
	uint16_t RA:1;     // recursion available
	uint16_t Z:1;	   // reserved for future
	uint16_t AD:1;	   // authenticated data
	uint16_t CD:1;	   // checking disabled
	uint16_t rcode:4;  // response code
#else
# error        "Please fix <bits/endian.h>"
#endif
    // uint16_t flags; // DNS flags
    uint16_t qd_count; // number of question entries
    uint16_t an_count; // number of answer entries
    uint16_t ns_count; // number of authority entries
    uint16_t ar_count; // number of additional entries
};

struct ip
  {
#if __BYTE_ORDER == __LITTLE_ENDIAN
    unsigned int ip_hl:4;                /* header length */
    unsigned int ip_v:4;                /* version */
#endif
#if __BYTE_ORDER == __BIG_ENDIAN
    unsigned int ip_v:4;                /* version */
    unsigned int ip_hl:4;                /* header length */
#endif
    u_int8_t ip_tos;                        /* type of service */
    u_short ip_len;                        /* total length */
    u_short ip_id;                        /* identification */
    u_short ip_off;                        /* fragment offset field */
#define        IP_RF 0x8000                        /* reserved fragment flag */
#define        IP_DF 0x4000                        /* dont fragment flag */
#define        IP_MF 0x2000                        /* more fragments flag */
#define        IP_OFFMASK 0x1fff                /* mask for fragmenting bits */
    u_int8_t ip_ttl;                        /* time to live */
    u_int8_t ip_p;                        /* protocol */
    u_short ip_sum;                        /* checksum */
    struct in_addr ip_src, ip_dst;        /* source and dest address */
  };

parameters get_app_config(int argc, char* argv[]);
void packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);

#endif //DNS_MONITOR_H
