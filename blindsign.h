#ifndef BLINDSIGN_H
#define BLINDSIGN_H

#include "setup.h"
#include "prepareblindsign.h" // KoRProof, PrepareBlindSignOutput
#include "keygen.h"           // EAKey => sgk1, sgk2
#include <vector>

/*
  CheckKoR (Alg.6) - 
   Girdi: 
     - params (TIACParams &)
     - com, comi, h (G1), pi_s=(c, s1, s2, s3)
   Çıktı: bool (true => πs=1, false => hata)
*/
bool CheckKoR(
    TIACParams &params,
    element_t com,
    element_t comi,
    element_t h,
    KoRProof &pi_s
);

/*
  BlindSignature: Alg.12'nin çıktısı (h, cm)
*/
struct BlindSignature {
    element_t h;   // G1
    element_t cm;  // G1
};

/*
  blindSign (Alg.12):
   Girdi:
    - params
    - PrepareBlindSignOutput: (com, comi, h, pi_s)
    - xm, ym (mpz_t) => EA otoritesinin gizli anahtarı
   Çıktı:
    - (h, cm)
*/
BlindSignature blindSign(
    TIACParams &params,
    PrepareBlindSignOutput &bsOut,
    mpz_t xm,
    mpz_t ym
);

#endif
