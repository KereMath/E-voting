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
    element_t comi;  // Alg.4 adım 2: g1^oi * h1^DID
    element_t h;     // Alg.4 adım 3: HashInG1(comi)
    element_t com;   // Alg.4 adım 5: g1^o * h^DID
    KoRProof  pi_s;  // Alg.4 adım 6: KoRProof (c, s1, s2, s3)
};

// prepareBlindSign (Algoritma 4)
//  Girdi: params (TIACParams), didStr (DID'in hex stringi)
//  Çıktı: (comi, h, com, pi_s)
PrepareBlindSignOutput prepareBlindSign(
    TIACParams &params, 
    const std::string &didStr
);

#endif
