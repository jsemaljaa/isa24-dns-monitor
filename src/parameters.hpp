/*
 * Project: DNS Monitor
 *
 * parameters.hpp
 * Created on 09/22/2024
 * 
 * @brief Declarations for program arguments parsing mechanism  
 * 
 * @author Alina Vinogradova <xvinog00@vutbr.cz>
*/

#ifndef PARAMETERS_H
#define PARAMETERS_H

#include <iostream>
#include <cstdlib>
#include <unistd.h>
#include <stdlib.h> // for exit()

typedef struct parameters {
    std::string interface;
    std::string pcapfile;
    bool verbose = false;
    std::string domainsfile;
    std::string translationsfile;
} parameters_t;

/*
 * @brief Parse program arguments
 * @param argc - arguments count
 * @param argv - arguments
 * @return Parameters data structure
*/
parameters_t parse(int argc, char* argv[]);

#endif //PARAMETERS_H
