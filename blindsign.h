#ifndef BLINDSIGN_H
#define BLINDSIGN_H

#include "setup.h"
#include "prepareblindsign.h"
#include <stdexcept>

/*
  BlindSignature: (Alg.12) 
   - h:  G1
   - cm: G1
*/
struct BlindSignature {
    element_t h;   // G1
    element_t cm;  // G1
};

/*
  blindSign:
    Girdi:
      - params
      - PrepareBlindSignOutput: (com, comi, h, pi_s, o) => from prepareBlindSign
      - x, y   => the master secret exponents (this time we skip partial shares)
    Çıktı:
      - BlindSignature { h, cm }
*/
BlindSignature blindSign(
    TIACParams &params,
    PrepareBlindSignOutput &bsOut,
    mpz_t x,
    mpz_t y
);

#endif
