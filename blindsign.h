#ifndef BLINDSIGN_H
#define BLINDSIGN_H

#include "setup.h"
#include "prepareblindsign.h"

// Final blind signature yapısı (Algorithm 12)
struct BlindSignature {
    element_t h;   // G₁ elemanı: blind sign mesajındaki h
    element_t cm;  // G₁ elemanı: final blind signature sonucu
};

// CheckKoR: Algoritma 6 – Temsil bilgisinin ispatının kontrolü
// Girdi: params, com, comi, h, πs
// Çıktı: true (ispat başarılı) veya false (hata)
bool checkKoR(TIACParams &params, element_t com, element_t comi, element_t h, Proof &pi_s);

// blindSign: Algoritma 12 – Final blind signature üretimi
// Girdi: BlindSignOutput (prepare blind sign çıktısı) ve EA otoritesinin secret değerleri xm, ym
// (Bu secret değerler, keygen aşamasında her EA tarafından belirlenen xi0 ve yi0’dır)
// Eğer CheckKoR geçerli değilse veya Hash(comi) ≠ h ise uyarı verir.
BlindSignature blindSign(TIACParams &params, BlindSignOutput &blindOut, element_t xm, element_t ym);

#endif
