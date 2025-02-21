#ifndef SETUP_H
#define SETUP_H

#include <pbc/pbc.h>
#include <gmp.h>
#include <cstring>

struct TIACParams {
    pairing_t pairing;   // PBC pairing objesi
    mpz_t prime_order;   // G1 grubunun gerçek mertebesi (p)
    element_t g1;        // G1 için sabit üreteç
    element_t h1;        // G1 için ikinci üreteç
    element_t g2;        // G2 için sabit üreteç
    element_t gT;        // GT için üreteç (pairing(g1, g2) ile elde edilir)
};

TIACParams setupParams();
void clearParams(TIACParams &params);
void hashG1(element_t out, element_t in);

#endif // SETUP_H
