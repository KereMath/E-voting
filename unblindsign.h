#ifndef UNBLINDSIGN_H
#define UNBLINDSIGN_H

#include "setup.h"
#include "blindsign.h"

/*
  UnblindSignInput (Algorithm 13 input):
    - comi: Commitment from prepareBlindSign (G1)
    - h: Hash(comi) from blindSign (G1)
    - cm: The partial signature from blindSign (G1)
    - o: The blinding factor (mpz_t)
    - alpha2, beta2, beta1: Verification keys for EA m (G2 for alpha2 and beta2, G1 for beta1)
    - DIDi: The voter’s DID (mpz_t)
*/
struct UnblindSignInput {
    element_t comi; 
    element_t h;
    element_t cm;
    mpz_t     o;
    element_t alpha2; // EA's α₂₍ₘ₎ (G2)
    element_t beta2;  // EA's β₂₍ₘ₎ (G2)
    element_t beta1;  // EA's β₁₍ₘ₎ (G1)
    mpz_t     DIDi;
};

/*
  UnblindSignature (Algorithm 13 output): σₘ = (h, sm)
*/
struct UnblindSignature {
    element_t h;
    element_t sm;
};

UnblindSignature unblindSignature(
    TIACParams &params,
    UnblindSignInput &in
);

#endif // UNBLINDSIGN_H
