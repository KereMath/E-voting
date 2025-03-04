#ifndef BLINDSIGN_H
#define BLINDSIGN_H

#include "setup.h"
#include "prepareblindsign.h" // KoRProof, PrepareBlindSignOutput
#include "keygen.h"           // EAKey => sgk1, sgk2
#include <vector>
#include <string>

/*
  elemToStrG1:
  element_t (G1 elemanı) değerini hex string'e çevirir.
  Bu fonksiyon blindsign.cpp içerisinde tanımlanacaktır.
*/
std::string elemToStrG1(element_t elem);

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
  Ek olarak, debug bilgileri saklanır; burada adminId ile ayrıca
  hangi voterdan geldiği bilgisi de main'de raporlanabilir.
*/
struct BlindSignature {
    element_t h;   // G1 (aynı h)
    element_t cm;  // G1 (hesaplanan cm)
    struct {
        int adminId;               // İmzayı üreten adminin numarası (0 tabanlı)
        int voterId;               // İmzayı alan seçmenin numarası (0 tabanlı)
        std::string checkKoR_result; // CheckKoR sonucu ve ara değerler
        std::string computed_hash_comi; // Hash(comi) sonucu (hesaplanan hprime)
        std::string hx;            // h^(xm) değeri
        std::string comy;          // com^(ym) değeri
        std::string computed_cm;   // Final cm = hx * comy
    } debug;
};

/*
  blindSign (Alg.12):
  Girdi:
    - params
    - PrepareBlindSignOutput: (com, comi, h, πs) (prepare aşamasından)
    - xm, ym (mpz_t): EA otoritesinin gizli anahtar bileşenleri
    - adminId (int): İmzayı üreten EA numarası (0 tabanlı)
    - voterId (int): İmzayı alan seçmenin numarası (0 tabanlı)
  Çıktı:
    - BlindSignature: (h, cm) ve debug bilgileri
*/
BlindSignature blindSign(
    TIACParams &params,
    PrepareBlindSignOutput &bsOut,
    mpz_t xm,
    mpz_t ym,
    int adminId,
    int voterId
);

#endif
