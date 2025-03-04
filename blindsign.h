#ifndef BLINDSIGN_H
#define BLINDSIGN_H

#include "setup.h"
#include "prepareblindsign.h" // KoRProof, PrepareBlindSignOutput
#include "keygen.h"           // EAKey => sgk1, sgk2
#include <vector>
#include <string>

/*
  CheckKoR (Alg.6):
  Girdi: (G1, p, g1, h, h1), com, comi, h, πs = (c, s1, s2, s3)
  Çıktı: bool (true => πs ispatı doğru, false => hata)
*/
bool CheckKoR(
    TIACParams &params,
    element_t com,
    element_t comi,
    element_t h,
    KoRProof &pi_s
);

/*
  BlindSignature: Alg.12'nin çıktısı (σ'_m = (h, cm))
*/
struct BlindSignature {
    element_t h;   // G1 (aynı h)
    element_t cm;  // G1 (hesaplanan cm)
};

/*
  blindSign (Alg.12):
  Girdi:
    - params
    - PrepareBlindSignOutput: (com, comi, h, πs) (prepare aşamasından)
    - xm, ym (mpz_t): EA otoritesinin gizli anahtar bileşenleri
  Çıktı:
    - BlindSignature: (h, cm)
  Not: Fonksiyon içinde ara değerler std::cout ile ekrana yazdırılmaktadır.
*/
BlindSignature blindSign(
    TIACParams &params,
    PrepareBlindSignOutput &bsOut,
    mpz_t xm,
    mpz_t ym
);

#endif
