#include "setup.h"
#include <iostream>
#include <stdexcept>
#include <fstream>

TIACParams setupParams() {
    TIACParams params;
    mpz_init(params.prime_order);
    pbc_param_t par;
    pbc_param_init_a_gen(par, 256, 512);
    pairing_init_pbc_param(params.pairing, par);
    mpz_set(params.prime_order, params.pairing->r);
    element_init_G1(params.g1, params.pairing);
    element_init_G1(params.h1, params.pairing);
    element_init_G2(params.g2, params.pairing);
    element_random(params.g1);
    element_random(params.h1);
    element_random(params.g2);
    pbc_param_clear(par);
    return params;
}

void clearParams(TIACParams &params) {
    element_clear(params.g1);
    element_clear(params.h1);
    element_clear(params.g2);
    mpz_clear(params.prime_order);
    pairing_clear(params.pairing);
}
