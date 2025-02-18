#ifndef PREPAREBLINDSIGN_H
#define PREPAREBLINDSIGN_H

#include "setup.h"
#include <string>

// Proof structure for KoR (Algorithm 5)
struct Proof {
    element_t c;   // Zₚ elemanı
    element_t s1;  // Zₚ elemanı
    element_t s2;  // Zₚ elemanı
    element_t s3;  // Zₚ elemanı
};

// Blind sign output structure (Algoritma 4)
struct BlindSignOutput {
    element_t com;   // G₁ elemanı (blind commitment)
    element_t comi;  // G₁ elemanı (commitment from oᵢ)
    element_t h;     // G₁ elemanı, h = Hash(comᵢ)
    Proof pi_s;      // Proof of knowledge for representation
};

// prepareBlindSign: Verilen setup parametreleri ve voterin (realID olarak) 11 haneli sayısal kimliği üzerinden
// kör imzalama mesajı (com, comᵢ, h) ve KoR kanıtı (πₛ) oluşturur.
BlindSignOutput prepareBlindSign(TIACParams &params, const std::string &realID);

#endif
