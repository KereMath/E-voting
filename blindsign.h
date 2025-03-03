#ifndef BLINDSIGN_H
#define BLINDSIGN_H

#include "setup.h"
#include "prepareblindsign.h"
#include <pbc/pbc.h>
#include <gmp.h>

// Blind Signature structure
struct BlindSignature {
    element_t h;  // Hash(comi)
    element_t cm; // Commitment raised to EA's private key
};

// Function to generate a blind signature
BlindSignature blindSign(
    TIACParams &params,
    PrepareBlindSignOutput &bsOut,
    mpz_t xm, // EA's private key xₘ
    mpz_t ym  // EA's private key yₘ
);

#endif
