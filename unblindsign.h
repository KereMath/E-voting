#ifndef UNBLINDSIGN_H
#define UNBLINDSIGN_H

#include "setup.h"
#include "blindsign.h"

/*
  UnblindSignInput: the inputs to Alg.13
   - comi (G1) : from prepareBlindSign
   - h    (G1) : from BlindSignature
   - cm   (G1) : from BlindSignature
   - o    (mpz_t) 
   - alpha2 (G2): partial or master key
   - beta2  (G2)
   - beta1  (G1)
   - DIDi   (mpz_t)
*/
struct UnblindSignInput {
    element_t comi; 
    element_t h;    
    element_t cm;   
    mpz_t     o;    
    element_t alpha2;
    element_t beta2;
    element_t beta1;
    mpz_t     DIDi; 
};

/*
  UnblindSignature: (h, sm) in G1
*/
struct UnblindSignature {
    element_t h; 
    element_t sm;
};

/*
  unblindSignature (Alg.13)
*/
UnblindSignature unblindSignature(
    TIACParams &params,
    UnblindSignInput &in
);

#endif // UNBLINDSIGN_H
