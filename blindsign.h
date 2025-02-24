#ifndef BLINDSIGN_H
#define BLINDSIGN_H

#include "setup.h"
#include "prepareblindsign.h"
#include "keygen.h"  // EAKey => xm, ym

/*
  CheckKoR (Algoritma 6) Girdi:
   - params (G1, p, g1, h, h1)
   - com, comi, pi_s (c, s1, s2, s3)
  Çıktı: bool (true = πs=1, false = "Hata")

  1) com''i = g1^s1 * h1^s2 * (comi^c)
  2) com''  = g1^s3 * h^s2  * (com^c)
  3) c' = Hash( g1, h, h1, com, com'', comi, com''i )
  4) if c' != c => return false
     else => return true
*/
bool CheckKoR(
    TIACParams &params,
    const element_t com, 
    const element_t comi,
    const element_t h,   // needed for hashing
    const KoRProof &pi_s // (c, s1, s2, s3)
);

/*
  BlindSignature (Alg. 12 çıktısı):
   - h (G1)
   - cm (G1)
*/
struct BlindSignature {
    element_t h; 
    element_t cm;
};

/*
  blindSign (Algoritma 12):
   Girdi:
    - params
    - PrepareBlindSignOutput (com, comi, h, pi_s)
    - EA otoritesi gizli anahtarı (x_m, y_m) -> "sgk1 = xm, sgk2 = ym"
   Çıktı:
    - (h, cm)

   Adımlar (özet):
    1) CheckKoR(...) = 1 değilse "Hata"
    2) hash(comi) != h ise "Hata"
    3) cm = h^xm * com^ym
    4) return (h, cm)
*/
BlindSignature blindSign(
    TIACParams &params,
    const PrepareBlindSignOutput &bsOut, // (com, comi, h, pi_s)
    const mpz_t xm,  // otoritenin gizli anahtarı 
    const mpz_t ym   // otoritenin gizli anahtarı
);

#endif
