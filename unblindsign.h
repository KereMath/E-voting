#ifndef UNBLINDSIGN_H
#define UNBLINDSIGN_H

#include "setup.h"
#include "blindsign.h"  // for BlindSignature definition
#include <stdexcept>

/*
  UnblindSignInput: Algoritma 13 girdileri
  - comi: (G1) PrepareBlindSignOutput'dan alınan orijinal "comi"
  - h   : (G1) EA’nın blindSign çıktısındaki h
  - cm  : (G1) EA’nın blindSign çıktısındaki cm
  - o   : (mpz_t) Seçmenin prepareBlindSign'da kullandığı rastgelelik
  - alpha2, beta2, beta1: EA'nın doğrulama anahtarları (vkm'ler)
       alpha2 = g2^(x_m), beta2 = g2^(y_m), beta1 = g1^(y_m)
  - DIDi: (mpz_t) Seçmenin DID’inin integer karşılığı (örn. dids[i].x)
*/
struct UnblindSignInput {
    element_t comi;    // G1
    element_t h;       // G1
    element_t cm;      // G1
    mpz_t      o;      // Rastgelelik (Zr)
    element_t alpha2;  // G2
    element_t beta2;   // G2
    element_t beta1;   // G1
    mpz_t      DIDi;   // Zr
};

/*
  UnblindSignature output: Algoritma 13 çıktısı
  - h:  (G1) – orijinal h değeri
  - sm: (G1) – unblind edilmiş imza (cm · (beta1)^(–o))
*/
struct UnblindSignature {
    element_t h;   // G1
    element_t sm;  // G1
};

/*
  Algoritma 13: TIAC Körleştirme Faktörünün Çıkarılması
  Girdi: UnblindSignInput in
  Çıktı: UnblindSignature
    1) Kontrol: Hash(comi) == h ?
    2) sm = cm * (beta1)^(-o)
    3) Kontrol: e(h, alpha2 · beta2^(DIDi)) == e(sm, g2) ?
       Eşitse (h, sm) döndür, aksi halde hata fırlat.
*/
UnblindSignature unblindSignature(
    TIACParams &params,
    const UnblindSignInput &in
);

#endif // UNBLINDSIGN_H
