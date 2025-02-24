#ifndef UNBLINDSIGN_H
#define UNBLINDSIGN_H

#include "setup.h"

// UnblindSignInput: Alg.13 girdileri
struct UnblindSignInput {
    element_t comi;    // PrepareBlindSignOutput'dan (aynı comi)
    // unblind aşamasında kullanılacak partial imza:
    element_t h;       // EA tarafından üretilen partial sig'dan h (blindSign çıktısı)
    element_t cm;      // EA tarafından üretilen partial sig'dan cm (blindSign çıktısı)
    // PrepareBlindSign aşamasında üretilen rastgele o (şimdi saklanıyor)
    mpz_t o;           // PrepareBlindSignOutput'dan saklanan o
    // EA'nın doğrulama anahtarları (vkm)
    element_t alpha2;  // EA için: keyOut.eaKeys[m].vkm1
    element_t beta2;   // EA için: keyOut.eaKeys[m].vkm2
    element_t beta1;   // EA için: keyOut.eaKeys[m].vkm3
    // DID (mod p) — seçmenin DID'i (örneğin dids[i].x)
    mpz_t DIDi;
};

// UnblindSignature output: Alg.13 çıktısı
struct UnblindSignature {
    element_t h;  // G1 (aynı h)
    element_t sm; // G1 (unblind edilmiş imza: cm * beta1^{-o})
};

/*
  Algoritma 13: TIAC Körleştirme Faktörünün Çıkarılması
  Girdi: 
    - UnblindSignInput in
  İşlem:
    1. Eğer Hash(comi) != h ise hata.
    2. sm = cm * (beta1)^{-o} hesapla.
    3. Eğer pairing doğrulaması: e(h, alpha2 * beta2^{DIDi}) == e(sm, g2) sağlanıyorsa,
       sigma_m = (h, sm) döndür, aksi halde hata.
*/
UnblindSignature unblindSignature(
    TIACParams &params,
    UnblindSignInput &in
);

#endif
