#ifndef PREPAREBLINDSIGN_H
#define PREPAREBLINDSIGN_H

#include "setup.h"
#include <string>

// KoRProof (πs): Temsil Bilgisinin İspatı
//   c, s1, s2, s3 ∈ Zr
struct KoRProof {
    element_t c;
    element_t s1;
    element_t s2;
    element_t s3;
};

// PrepareBlindSignOutput:
//   - comi (G1) : İlk commitment
//   - h (G1)    : comi'den hash fonksiyonu ile G1'e maplenen değer
//   - com (G1)  : İkinci commitment (g1^o * h^DID)
//   - pi_s      : KoRProof = (c, s1, s2, s3)
struct PrepareBlindSignOutput {
    element_t comi;
    element_t h;
    element_t com;
    KoRProof  pi_s;
};

// prepareBlindSign:
//  Girdi : params (TIACParams), didStr (ör. SHA-512 hex string DID)
//  Çıktı : PrepareBlindSignOutput
//  
//  Algoritma 4: Kör İmzalama Mesajının Oluşturulması
//    1) Rastgele oi ∈ Zp
//    2) comi = g1^oi * h1^DID
//    3) h = HashInG1(comi) (örn. element_from_hash)
//    4) Rastgele o ∈ Zp
//    5) com = g1^o * h^DID
//    6) πs = KoR(com, comi) (Algoritma 5)
//    7) return (com, comi, h, πs)
PrepareBlindSignOutput prepareBlindSign(const TIACParams &params, const std::string &didStr);

#endif
