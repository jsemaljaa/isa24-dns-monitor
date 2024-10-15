//
// Created by Alina Vinogradova on 9/21/2024.
//

#ifndef DNS_HEADER_H
#define DNS_HEADER_H

#include <cstdint>

// https://mislove.org/teaching/cs4700/spring11/handouts/project1-primer.pdf 
// https://www.catchpoint.com/blog/how-dns-works

// changed the structure according to this: 
// https://stackoverflow.com/questions/59594815/dns-query-format-little-big-endian-problem-in-header-structure

class DnsHeader {
	public:
		uint16_t id;
		uint16_t qd_count;
    	uint16_t an_count;
    	uint16_t ns_count;
    	uint16_t ar_count;

		uint16_t qr;
		uint16_t opcode;
		uint16_t aa;
		uint16_t tc;
		uint16_t rd;
		uint16_t ra;
		uint16_t z;
		uint16_t ad;
		uint16_t cd;
		uint16_t rcode;

		DnsHeader(struct dns_header *dnsh);

	private:
		uint16_t get_qr(uint16_t flags);
		uint8_t get_opcode(uint16_t flags);
		uint16_t get_aa(uint16_t flags);
		uint16_t get_tc(uint16_t flags);
		uint16_t get_rd(uint16_t flags);
		uint16_t get_ra(uint16_t flags);
		uint16_t get_z(uint16_t flags);
		uint16_t get_ad(uint16_t flags);
		uint16_t get_cd(uint16_t flags);
		uint8_t get_rcode(uint16_t flags);
};


struct dns_header {
    uint16_t id;
    uint16_t flags;
    uint16_t qd_count; // number of question entries
    uint16_t an_count; // number of answer entries
    uint16_t ns_count; // number of authority entries
    uint16_t ar_count; // number of additional entries
};


// struct dns_header {
//     uint16_t id;       // identification number
// #if __BYTE_ORDER == __BIG_ENDIAN
// 	uint16_t RD:1;     // recursion desired
// 	uint16_t TC:1; 	   // truncated message
// 	uint16_t AA:1;	   // authoritative answer
// 	uint16_t opcode:4; // purpose of message
// 	uint16_t qr:1;	   // query/response flag
// 	uint16_t rcode:4;  // response code
// 	uint16_t CD:1;	   // checking disabled
// 	uint16_t AD:1;	   // authenticated data
// 	uint16_t Z:1;	   // reserved for future
// 	uint16_t RA:1;     // recursion available
// #elif __BYTE_ORDER == __LITTLE_ENDIAN
// 	uint16_t qr:1;     // recursion desired
// 	uint16_t opcode:4; // purpose of message
// 	uint16_t AA:1;	   // authoritative answer
// 	uint16_t TC:1; 	   // truncated message
// 	uint16_t RD:1;     // recursion desired
// 	uint16_t RA:1;     // recursion available
// 	uint16_t Z:1;	   // reserved for future
// 	uint16_t AD:1;	   // authenticated data
// 	uint16_t CD:1;	   // checking disabled
// 	uint16_t rcode:4;  // response code
// #else
// # error        "Please fix <bits/endian.h>"
// #endif
//     // uint16_t flags; // DNS flags
//     uint16_t qd_count; // number of question entries
//     uint16_t an_count; // number of answer entries
//     uint16_t ns_count; // number of authority entries
//     uint16_t ar_count; // number of additional entries
// };

#endif //DNS_HEADER_H