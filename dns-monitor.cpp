//
// Created by Alina Vinogradova on 9/21/2024.
//

#include "dns-monitor.h"

// g++ -o dns-monitor dns-monitor.cpp -lpcap


int main(int argc, char* argv[]) {
    parameters config = parse(argc, argv);

    if (!config.interface.empty()) {
        std::cout << "Interface: " << config.interface << std::endl;
    }

    if (!config.pcapfile.empty()) {
        std::cout << "PCAP File: " << config.pcapfile << std::endl;
    }

    if (config.verbose) {
        std::cout << "Verbose Mode: ON" << std::endl;
    }

    if (!config.domainsfile.empty()) {
        std::cout << "Domains File: " << config.domainsfile << std::endl;
    }

    if (!config.translationsfile.empty()) {
        std::cout << "Translations File: " << config.translationsfile << std::endl;
    }

    return 0;
}
