#ifndef BLINDSIGN_H
#define BLINDSIGN_H

#include "setup.h"
#include "prepareblindsign.h"

/*
  BlindSignature => (h, cm) from Alg.12
*/
struct BlindSignature {
    element_t h;   // G1
    element_t cm;  // G1
};

/*
  blindSign (single-authority):
   - Girdi:
     - params
     - PrepareBlindSignOutput (com, comi, h, o, pi_s)
     - x, y => master gizli anahtar
   - Çıktı: (h, cm) = (h, h^x * com^y)
*/
BlindSignature blindSign(
    TIACParams &params,
    PrepareBlindSignOutput &bsOut,
    mpz_t x,
    mpz_t y
);

#endif
