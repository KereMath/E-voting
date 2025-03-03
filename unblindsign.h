#ifndef UNBLINDSIGN_H
#define UNBLINDSIGN_H

#include "setup.h"
#include "blindsign.h"

// Structure for unblinding input
struct UnblindSignInput {
    element_t comi;
    element_t h;
    element_t cm;
    mpz_t     o;
    element_t alpha2; // G2: g2^(xₘ)
    element_t beta2;  // G2: g2^(yₘ)
    element_t beta1;  // G1: g1^(yₘ)
    mpz_t     DIDi;   // Voter's DID
};

// Structure for unblinded signature output
struct UnblindSignature {
    element_t h;
    element_t sm;
};

UnblindSignature unblindSignature(
    TIACParams &params,
    UnblindSignInput &in
);

#endif
