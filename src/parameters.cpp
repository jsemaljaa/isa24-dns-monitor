/*
 * Project: DNS Monitor
 *
 * parameters.cpp
 * Created on 09/22/2024
 * 
 * @brief Implementation of program arguments parsing mechanism  
 * 
 * @author Alina Vinogradova <xvinog00@vutbr.cz>
*/

#include "parameters.hpp"

parameters_t parse(int argc, char* argv[]) {
    parameters_t p;
    int opt;

    while ((opt = getopt(argc, argv, "i:p:vd:t:")) != -1) {
        switch (opt) {
            case 'i':
                p.interface = optarg;
                break;
            case 'p':
                p.pcapfile = optarg;
                break;
            case 'v':
                p.verbose = true;
                break;
            case 'd':
                p.domainsfile = optarg;
                break;
            case 't':
                p.translationsfile = optarg;
                break;
            default:
                std::cerr << "Usage: ./dns-monitor (-i <interface> | -p <pcapfile>) [-v] [-d <domainsfile>] [-t <translationsfile>]\n";
                exit(EXIT_FAILURE);
        }
    }

    // Ensure either interface or pcap file is provided (but not both)
    if ((p.interface.empty() && p.pcapfile.empty()) || (!p.interface.empty() && !p.pcapfile.empty())) {
        std::cerr << "Error: You must specify either an interface (-i) or a PCAP file (-p). (but not both)\n";
        exit(EXIT_FAILURE);
    }

    return p;
}