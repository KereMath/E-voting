#ifndef PREPAREBLINDSIGN_H
#define PREPAREBLINDSIGN_H

#include "setup.h"
#include <string>

// Proof yapısı (Algorithm 5)
struct Proof {
    element_t c;   // Zₚ elemanı
    element_t s1;  // Zₚ elemanı
    element_t s2;  // Zₚ elemanı
    element_t s3;  // Zₚ elemanı
};

// BlindSignOutput yapısı (Algorithm 4)
struct BlindSignOutput {
    element_t com;   // G₁ elemanı: blind commitment (adım 5)
    element_t comi;  // G₁ elemanı: commitment from oᵢ (adım 2)
    element_t h;     // G₁ elemanı: h = Hash(comi) (adım 3)
    Proof pi_s;      // Proof: KoR ispatı (adım 6)
};

// prepareBlindSign: Verilen setup parametreleri ve voterin gerçek ID (11 haneli string) üzerinden
// prepare blind sign mesajı ve kanıtı (BlindSignOutput) üretir.
BlindSignOutput prepareBlindSign(TIACParams &params, const std::string &realID);

#endif
