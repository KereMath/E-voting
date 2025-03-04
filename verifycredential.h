#ifndef VERIFYCREDENTIAL_H
#define VERIFYCREDENTIAL_H

#include "setup.h"
#include "provecredential.h"
#include <string>

/*
  verifyCredential: Algoritma 18 Coconut İmza Doğrulaması
  Girdi: σRnd = (σ'', k), π_v (proveCredential çıktısı)
  Çıktı: true (1) veya false (0)
  İşlem:
    Eğer (π_v == 1) (yani proveCredential aşamasında üretilen proof geçerliyse) 
    ve e(h'', k) = e(s'', g₂) ise doğrulama PASSED; aksi takdirde FAILED.
    (Burada π_v için ek bir kontrol yapılmıyor; sadece pairing kontrolü yapılıyor.)
*/
bool verifyCredential(
    TIACParams &params,
    ProveCredentialOutput &pOut
);

#endif
