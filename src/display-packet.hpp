/*
 * Project: DNS Monitor
 *
 * display-packet.hpp
 * Created on 01/11/2024
 * 
 * @brief Declarations of functions and data structures to display a DNS packet
 *
 * @author Alina Vinogradova <xvinog00@vutbr.cz>
*/

#ifndef DISPLAY_PACKET_H
#define DISPLAY_PACKET_H

#include "dns-packet.hpp"
#include "parameters.hpp"

void display_dns_packet_short(DnsPacket dnspacket);
void display_dns_packet_verbose(DnsPacket dnspacket);

#endif //DISPLAY_PACKET_H
