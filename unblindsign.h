#ifndef UNBLINDSIGN_H
#define UNBLINDSIGN_H

#include "setup.h"

/*
  Coconut / TIAC vkm = (alpha2, beta2, beta1)
  UnblindSignInput:
    - comi   : G1  (Hazırlık aşamasında üretilen comi)
    - h      : G1  (same h from Alg.12)
    - o      : mpz_t (prepareBlindSign aşamasındaki rastgele üs)
    - alpha2 : G2
    - beta2  : G2
    - beta1  : G1
    - cm     : G1 (Alg.12 çıktısı: c_m)
    - DIDi   : mpz_t (kullanıcı DID'i mod p, eğer doğrulamada gerekirse)
*/

struct UnblindSignInput {
    element_t comi;
    element_t h;
    mpz_t     o;
    element_t alpha2; // G2
    element_t beta2;  // G2
    element_t beta1;  // G1
    element_t cm;     // Alg.12 çıktısı (EA partial sig)
    mpz_t     DIDi;   // DID mod p (bazı doğrulama formüllerinde lazım)
};

/*
  UnblindSignature (Alg.13 çıktısı) = (h, s_m)

  Not: Bazı tanımlarda "sigma_m = (h, s_m)".
*/
struct UnblindSignature {
    element_t h;  // G1
    element_t sm; // G1
};

/*
  unblindSignature (Alg.13):
    Girdi: 
      (comi, h, g2, o, vkm=(alpha2, beta2, beta1), sigma'_m=(h, cm))
    Çıktı:
      sigma_m = (h, sm)

   1) if Hash(comi) != h => Hata
   2) sm = cm * (beta1^{-o})
   3) check e(h, alpha2 * (beta2^{DID})) == e(sm, g2)?
      - e(h, alpha2 . beta2^DID ) =?= e(sm, g2)
   4) if eq => return (h, sm), else => hata
*/
UnblindSignature unblindSignature(
    TIACParams &params,
    const UnblindSignInput &in
);

#endif
