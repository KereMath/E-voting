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
  BlindSignature: Algoritma 12'nin çıktısı (σ'_m = (h, cm))
  Ek olarak, debug bilgileri saklanır; burada adminId da yer alır.
*/
struct BlindSignature {
    element_t h;   // G1 (aynı h)
    element_t cm;  // G1 (hesaplanan cm)
    // Debug alanı: hesaplama ara değerleri ve imzalayan adminin numarası
    struct {
        int adminId;               // İmzayı üreten adminin numarası (0 tabanlı)
        std::string checkKoR_result; // CheckKoR sonucu ve ara değerler
        std::string computed_hash_comi; // Hash(comi) sonucu
        std::string hx;            // h^(xm)
        std::string comy;          // com^(ym)
        std::string computed_cm;   // Sonuç cm = hx * comy
    } debug;
};

/*
  blindSign (Alg.12):
  Girdi:
    - params
    - PrepareBlindSignOutput: (com, comi, h, πs) (prepare aşamasından)
    - xm, ym (mpz_t): EA otoritesinin gizli anahtar bileşenleri
    - adminId (int): Bu imzayı üreten EA numarası (0 tabanlı)
  Çıktı:
    - BlindSignature: (h, cm) ve debug bilgileri
  Not: Fonksiyon içerisinde ara değerler std::cout ile de ekrana yazdırılıyor.
*/
BlindSignature blindSign(
    TIACParams &params,
    PrepareBlindSignOutput &bsOut,
    mpz_t xm,
    mpz_t ym,
    int adminId
);

#endif
