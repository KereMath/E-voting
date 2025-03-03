#ifndef UNBLINDSIGN_H
#define UNBLINDSIGN_H

#include "setup.h"
#include "blindsign.h"

/*
  UnblindSignInput: the inputs to Alg.13
   - comi (G1) : from prepareBlindSign (the DID commitment)
   - h    (G1) : from BlindSignature (should match Hash(comi))
   - cm   (G1) : from BlindSignature
   - o    (mpz_t) : the random 'o' used in prepareBlindSign
   - alpha2 (G2): = g2^(x_m)  [ or combined / or master key alpha2 = g2^x ]
   - beta2  (G2): = g2^(y_m)  [ or combined / or master key beta2 = g2^y ]
   - beta1  (G1): = g1^(y_m)  [ or combined / or master key beta1 = g1^y ]
   - DIDi   (mpz_t) : the DID integer (from createDID)
*/
struct UnblindSignInput {
    element_t comi;  // G1
    element_t h;     // G1
    element_t cm;    // G1
    mpz_t     o;     // random factor from prepareBlindSign
    element_t alpha2;// G2
    element_t beta2; // G2
    element_t beta1; // G1
    mpz_t     DIDi;  // Zr
};

/*
  UnblindSignature: output of Alg.13
   - h  (G1) same as input
   - sm (G1) unblinded signature
*/
struct UnblindSignature {
    element_t h; 
    element_t sm;
};

/*
  unblindSignature (Alg.13):
    1) if Hash(comi) != h => "Hata"
    2) sm = cm * (beta1^(-o))
    3) if e(h, alpha2 * (beta2^DIDi)) == e(sm, g2) => return (h, sm) else "Hata"
*/
UnblindSignature unblindSignature(
    TIACParams &params,
    UnblindSignInput &in
);

#endif // UNBLINDSIGN_H
