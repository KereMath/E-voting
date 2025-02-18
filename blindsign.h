#ifndef BLINDSIGN_H
#define BLINDSIGN_H

#include "setup.h"
#include "prepareblindsign.h"
#include <string>

// Final blind signature yapısı (Algorithm 12)
struct BlindSignature {
    element_t h;   // G₁ elemanı (blind sign mesajından h)
    element_t cm;  // G₁ elemanı (blind signature sonucu)
};

// CheckKoR: Algoritma 6 – Temsil bilgisinin ispatının kontrolü
// Girdi: params, com, comi, h, πs
// Çıktı: true (ispat başarılı) veya false (hata)
bool checkKoR(TIACParams &params, element_t com, element_t comi, element_t h, Proof &pi_s);

// blindSign: Algoritma 12 – Final blind signature üretimi
// Girdi: BlindSignOutput (prepare blind sign çıktısı), voterin secret değerleri xm, ym
// (Örnek amaçlı: xm, ym olarak DID üretiminde oluşturulan x değeri kullanılıyor)
// Eğer CheckKoR geçerli değilse veya Hash(comi) ≠ h ise hata döndürür.
BlindSignature blindSign(TIACParams &params, BlindSignOutput &blindOut, element_t xm, element_t ym);

#endif
