#ifndef UNBLINDSIGN_H
#define UNBLINDSIGN_H

#include "setup.h"

// vkm = (alpha2, beta2, beta1) gibi parametreler

struct UnblindSignInput {
    element_t comi;   // G1
    element_t h;      // G1
    mpz_t     o;      // Rastgele o
    element_t alpha2; // G2
    element_t beta2;  // G2
    element_t beta1;  // G1
    element_t cm;     // G1
    mpz_t     DIDi;   // DID mod p
};

struct UnblindSignature {
    element_t h; 
    element_t sm;
};

// Burada "const UnblindSignInput&" yerine "UnblindSignInput&" (veya kopya) olmalı!
UnblindSignature unblindSignature(
    TIACParams &params,
    UnblindSignInput &in  // <-- const kaldırılıyor
);

#endif
