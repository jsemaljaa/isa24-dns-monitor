/*
 * Project: DNS Monitor
 *
 * display-packet.cpp
 * Created on 01/11/2024
 * 
 * @brief Implementation of functions to display a DNS packet
 *
 * @author Alina Vinogradova <xvinog00@vutbr.cz>
*/

#include "display-packet.hpp"

using namespace std;

void display_dns_packet_short(DnsPacket dnspacket) {
    cout << dnspacket.header->timestamp << " ";
    cout << dnspacket.header->src_ip << " -> " << dnspacket.header->dst_ip << " ";
    cout << "(" << ((dnspacket.header->get_qr() == 1) ? "R" : "Q") << " ";
    cout << dnspacket.header->qd_count << "/";
    cout << dnspacket.header->an_count << "/";
    cout << dnspacket.header->ns_count << "/";
    cout << dnspacket.header->ar_count << ")" << endl;
}

void display_dns_packet_verbose(DnsPacket dnspacket) {

    // Don't display a packet, if every single record in this packet is not supported 
    if (dnspacket.questions.empty() && dnspacket.answers.empty() && dnspacket.authorities.empty() && dnspacket.additionals.empty())
        return;
        
    cout << "Timestamp: " << dnspacket.header->timestamp << endl;
    cout << "SrcIP: " << dnspacket.header->src_ip << endl;
    cout << "DstIP: " << dnspacket.header->dst_ip << endl;
    cout << "SrcPort: UDP/" << dnspacket.header->src_port << endl;
    cout << "DstPort: UDP/" << dnspacket.header->dst_port << endl;
    cout << "Identifier: 0x" << hex << uppercase << setw(4) << setfill('0') << dnspacket.header->id << dec << endl;
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

    if (!dnspacket.questions.empty()) {
        cout << "[Question Section]" << endl;
        for (const std::string& q : dnspacket.questions) {
            if (!q.empty()) {
                cout << q;
            } 
        }
        if (!(dnspacket.answers.empty() && dnspacket.authorities.empty() && dnspacket.additionals.empty())) {
            cout << endl;
        }
    }

    if (!dnspacket.answers.empty()) {
        cout << "[Answer Section]" << endl;
        for (const string &a : dnspacket.answers) {
            if (!a.empty()) {
                cout << a;
            }
        }
        if (!(dnspacket.authorities.empty() && dnspacket.additionals.empty())) {
            cout << endl;
        }
    }

    if (!dnspacket.authorities.empty()) {
        cout << "[Authority Section]" << endl;
        for (const string &au : dnspacket.authorities) {
            if (!au.empty()) {
                cout << au;
            } 
        }
        if (!(dnspacket.additionals.empty())) {
            cout << endl;
        }
    }

    if (!dnspacket.additionals.empty()) {
        cout << "[Additional Section]" << endl;
        for (const string &ad : dnspacket.additionals) {
            if (!ad.empty()) {
                cout << ad;
            } 
        }
    }
    cout << "====================" << endl;
}