#ifndef PREPAREBLINDSIGN_H
#define PREPAREBLINDSIGN_H

#include "setup.h"
#include <string>

// KoRProof (πs): c, s1, s2, s3 ∈ Zr
struct KoRProof {
    element_t c;
    element_t s1;
    element_t s2;
    element_t s3;
};

// Kör imzalama ön-hazırlık çıktısı:
//  - comi (G1)
//  - h (G1)
//  - com (G1)
//  - pi_s (KoRProof)
struct PrepareBlindSignOutput {
    element_t comi;
    element_t h;
    element_t com;
    KoRProof  pi_s;
};

// prepareBlindSign:
//  Girdi: params (TIACParams), didStr (DID'in hex stringi)
//  Çıktı: (comi, h, com, pi_s) -- Algoritma 4
PrepareBlindSignOutput prepareBlindSign(
    TIACParams &params, 
    const std::string &didStr
);

#endif
