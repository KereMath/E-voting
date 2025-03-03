#ifndef UNBLINDSIGN_H
#define UNBLINDSIGN_H

#include "setup.h"

/* 
  UnblindSignInput: Algoritma 13 girdileri
  - comi: PrepareBlindSignOutput'dan alınan orijinal comi (G1)
  - h: EA’nın blindSign (partial signature) çıktısından alınan h (G1)
  - cm: EA’nın blindSign çıktısından alınan cm (G1)
  - o: PrepareBlindSignOutput’da hesaplanıp saklanan o (mpz_t)
  - alpha2, beta2, beta1: EA'nın doğrulama anahtarları (vkm); 
       alpha2 = g2^(xm), beta2 = g2^(ym), beta1 = g1^(ym)
  - DIDi: Seçmenin DID’inin (mod p) mpz_t temsili (örneğin dids[i].x)
*/
struct UnblindSignInput {
    element_t comi;    // G1
    element_t h;       // G1
    element_t cm;      // G1
    mpz_t o;           // Rastgele seçilen o (PrepareBlindSignOutput'dan)
    element_t alpha2;  // EA doğrulama anahtarından: g2^(xm)
    element_t beta2;   // EA doğrulama anahtarından: g2^(ym)
    element_t beta1;   // EA doğrulama anahtarından: g1^(ym)
    mpz_t DIDi;        // Seçmenin DID (mod p)
};

/* 
  UnblindSignature output: Algoritma 13 çıktısı
  - h: (G1) – orijinal h değeri
  - sm: (G1) – unblind edilmiş imza (cm · (beta1)^(–o))
*/
struct UnblindSignature {
    element_t h;
    element_t sm;
};

/*
  Algoritma 13: TIAC Körleştirme Faktörünün Çıkarılması
  Girdi: UnblindSignInput in
  İşlem:
    1. Eğer Hash(comi) ≠ h ise hata.
    2. sm = cm · (beta1)^(–o) hesapla.
    3. Eğer pairing doğrulaması: e(h, alpha2 · (beta2)^(DIDi)) == e(sm, g2) sağlanıyorsa,
       (h, sm) döndür; aksi halde hata.
*/
UnblindSignature unblindSignature(
    TIACParams &params,
    UnblindSignInput &in
);

#endif
