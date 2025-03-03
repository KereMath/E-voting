#ifndef BLINDSIGN_H
#define BLINDSIGN_H

#include "setup.h"
#include "prepareblindsign.h" // For PrepareBlindSignOutput and KoRProof
#include "keygen.h"           // For EAKey (if needed)
#include <vector>

/*
  BlindSignature (Algorithm 12 output): σ′ₘ = (h, cm)
  Here, we set h = Hash(comi) and compute cm = (com_blind)^(xₘ).
  (Note: In this minimal fix we use only the EA’s sgk1 (xₘ).)
*/
struct BlindSignature {
    element_t h;   // G1
    element_t cm;  // G1
    // Optionally, you might add an adminId field here if desired.
};

BlindSignature blindSign(
    TIACParams &params,
    PrepareBlindSignOutput &bsOut,
    mpz_t xm, // EA's secret xₘ
    mpz_t ym  // EA's secret yₘ (currently not used)
);

#endif // BLINDSIGN_H
