#ifndef UNBLINDSIGN_H
#define UNBLINDSIGN_H

#include "setup.h"
#include "blindsign.h"

/*
  UnblindSignInput:
   - comi (G1)
   - h    (G1)
   - cm   (G1)
   - o    (mpz_t) from prepareBlindSign
   - alpha2 = g2^x
   - beta2  = g2^y
   - beta1  = g1^y
   - DIDi   = (mpz_t) from createDID
*/
struct UnblindSignInput {
    element_t comi;
    element_t h;
    element_t cm;
    mpz_t     o;
    element_t alpha2; // G2
    element_t beta2;  // G2
    element_t beta1;  // G1
    mpz_t     DIDi;   // Zr
};

/*
  UnblindSignature output: (h, sm)
*/
struct UnblindSignature {
    element_t h;
    element_t sm;
};

/*
  unblindSignature (Alg.13 single-authority):
   1) Check hash(comi) == h
   2) sm = cm * (beta1^(-o))
   3) if e(h, alpha2 * beta2^DIDi) == e(sm, g2) => ok else error
*/
UnblindSignature unblindSignature(
    TIACParams &params,
    UnblindSignInput &in
);

#endif
