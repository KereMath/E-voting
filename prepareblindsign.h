#ifndef PREPAREBLINDSIGN_H
#define PREPAREBLINDSIGN_H

#include "setup.h"
#include <string>
#include <vector>

struct KoRProof {
    element_t c;
    element_t s1;
    element_t s2;
    element_t s3;
};

struct PrepareBlindSignOutput {
    element_t comi;
    element_t h;
    element_t com;
    KoRProof pi_s;
    mpz_t o;     // Blind factor needed for later operations
    std::string com_str; // String representation of com for later verification
};

PrepareBlindSignOutput prepareBlindSign(
    TIACParams &params, 
    const std::string &didStr
);

#endif