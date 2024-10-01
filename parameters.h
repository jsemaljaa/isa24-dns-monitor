//
// Created by Alina Vinogradova on 9/22/2024.
//

#ifndef PARAMETERS_H
#define PARAMETERS_H

#include <iostream>
#include <cstdlib>
#include <unistd.h>

struct parameters {
    std::string interface;
    std::string pcapfile;
    bool verbose = false;
    std::string domainsfile;
    std::string translationsfile;
};

parameters parse(int argc, char* argv[]);

#endif //PARAMETERS_H
