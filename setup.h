#ifndef SETUP_H
#define SETUP_H

#include <pbc/pbc.h>
#include <gmp.h>

struct TIACParams {
    pairing_t pairing; 
    mpz_t prime_order;
    element_t g1;
    element_t g2;
    element_t h1;
};

TIACParams setupParams();

void clearParams(TIACParams &params);

#endif
