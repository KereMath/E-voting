#ifndef DIDGEN_H
#define DIDGEN_H

#include "setup.h"
#include <string>

struct DID {
    mpz_t x;
    std::string did;
};

DID createDID(const TIACParams &params, const std::string &userID);

#endif
