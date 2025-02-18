#ifndef BLINDSIGN_H
#define BLINDSIGN_H

#include "setup.h"
#include "prepareblindsign.h"
#include <string>

// Yapı: Final blind signature (Algoritma 12)
struct BlindSignature {
    element_t h;   // G1 elemanı (blind sign mesajından h)
    element_t cm;  // G1 elemanı (blind signature sonucu)
};

// CheckKoR: Algoritma 6 – Temsil bilgisinin ispatının kontrolü  
// Girdi: params, com, comi, h, πs  
// Çıktı: true (ispat geçerli) veya false (hata)
bool checkKoR(TIACParams &params, element_t com, element_t comi, element_t h, Proof &pi_s);

// blindSign: Algoritma 12 – Kör imzalama  
// Girdi: prepareBlindSign() çıktısı (BlindSignOutput) ve voterin secret değerleri (xm, ym)
// Çıktı: BlindSignature σ'_m = (h, cm)
//       cm = h^(xm) · g1^(ym), ancak önce CheckKoR() ve h==Hash(comi) kontrolü yapılır.
BlindSignature blindSign(TIACParams &params, BlindSignOutput &blindOut, element_t xm, element_t ym);

#endif
