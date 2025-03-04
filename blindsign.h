#ifndef BLINDSIGN_H
#define BLINDSIGN_H

#include "setup.h"
#include "prepareblindsign.h" // KoRProof, PrepareBlindSignOutput
#include "keygen.h"           // EAKey => sgk1, sgk2
#include <vector>
#include <string>

/*
  BlindSignDebug:
  Bu yapı, Kör İmzalama algoritmasında hesaplanan ara değerleri
  (örneğin CheckKoR içindeki ara hesaplamalar, hash değerleri, hesaplanan hx, comy, cm vb.)
  saklamak için kullanılacaktır.
*/
struct BlindSignDebug {
    std::string checkKoR_result;     // CheckKoR fonksiyonunun sonucu ("başarılı" veya hata açıklaması)
    std::string checkKoR_comi_double;  // CheckKoR'da hesaplanan comi'' (comi_double)
    std::string checkKoR_com_double;   // CheckKoR'da hesaplanan com'' (com_double)
    std::string checkKoR_cprime;       // CheckKoR'da hesaplanan c' değeri
    std::string computed_hash_comi;    // BlindSign fonksiyonunda Hash(comi) sonucu
    std::string hx;                  // h^(xm) değeri
    std::string comy;                // com^(ym) değeri
    std::string computed_cm;         // Hesaplanan cm (hx * comy)
};

/*
  BlindSignature: Algoritma 12'nin çıktısı
  σ'_m = (h, cm)
*/
struct BlindSignature {
    element_t h;   // G1 (aynı h)
    element_t cm;  // G1 (hesaplanan cm)
    BlindSignDebug debug; // Detaylı ara değerlerin saklandığı debug yapısı
};

/*
  CheckKoR (Alg.6)
  Girdi: (G1, p, g1, h, h1), com, comi, h, πs = (c, s1, s2, s3)
  Çıktı: Eğer KoR ispatı doğru ise true; aksi halde false.
  Ek olarak, tüm ara hesaplama değerleri "debug_info" string'ine aktarılır.
*/
bool CheckKoR(
    TIACParams &params,
    element_t com,
    element_t comi,
    element_t h,
    KoRProof &pi_s,
    std::string &debug_info
);

/*
  blindSign (Alg.12):
  Girdi:
    - params
    - PrepareBlindSignOutput: (com, comi, h, πs, debug) (prepare aşamasından)
    - xm, ym (mpz_t): EA otoritesinin gizli anahtar bileşenleri
  Çıktı:
    - BlindSignature: σ'_m = (h, cm) ve debug bilgileri
*/
BlindSignature blindSign(
    TIACParams &params,
    PrepareBlindSignOutput &bsOut,
    mpz_t xm,
    mpz_t ym
);

#endif
