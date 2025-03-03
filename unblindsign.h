#ifndef UNBLINDSIGN_H
#define UNBLINDSIGN_H

#include "setup.h"
#include "blindsign.h"

/*
  UnblindSignInput: the inputs to Alg.13
*/
struct UnblindSignInput {
    element_t comi; 
    element_t h;
    element_t cm;
    mpz_t     o;    
    element_t alpha2; // G2
    element_t beta2;  // G2
    element_t beta1;  // G1
    mpz_t     DIDi;   // DID in mpz
};

struct UnblindSignature {
    element_t h; 
    element_t sm;
};

UnblindSignature unblindSignature(
    TIACParams &params,
    UnblindSignInput &in
);
struct BlindSignature {
  element_t h;   // G1
  element_t cm;  // G1
};

#endif
