#ifndef AGGREGATE_H
#define AGGREGATE_H

#include "setup.h"
#include "keygen.h"   // MasterVerKey tanımlı
#include "unblindsign.h"
#include <vector>
#include <string>
#include <gmp.h>
#include <pbc/pbc.h>

/*
  AggregateSignature: Nihai aggregate imza σ = (h, s)
  ve debug alanında hesaplama detaylarını saklar.
*/
struct AggregateSignature {
    element_t h;           // Tüm partial imzaların ortak h değeri
    element_t s;           // Her partial imzanın s_m değerlerinin Lagrange katsayılarıyla ağırlıklı çarpımından elde edilen s
    std::string debug_info;// Hesaplama sırasında toplanan debug çıktıları (λ değerleri, s_m^(λ) vb.)
};

/*
  aggregateSign: Her seçmenin unblind edilmiş imza parçalarını Lagrange interpolasyonu kullanarak aggregate eder.
  
  Girdi:
    - params: TIAC parametreleri.
    - partialSigsWithAdmins: Her seçmenin unblind edilmiş imza parçalarını içeren vector<pair<Admin ID, UnblindSignature>>.
         (Her pair’in first’i admin ID’si, second’ı ilgili UnblindSignature)
    - mvk: Master verification key (mvk = (α₂, β₂, β₁)); burada mvk.vkm1 = α₂, mvk.vkm2 = β₂ kullanılacak.
    - didStr: Seçmenin DID (hex string) (protokolde yer alabilir, bu örnekte kullanılmıyor).
    - groupOrder: Grup mertebesi (p) mpz_t.
  Çıktı:
    - AggregateSignature: Nihai aggregate imza σ = (h, s) ve debug bilgileri.
*/
AggregateSignature aggregateSign(
    TIACParams &params,
    const std::vector<std::pair<int, UnblindSignature>> &partialSigsWithAdmins,
    MasterVerKey &mvk,
    const std::string &didStr,
    const mpz_t groupOrder
);

#endif
