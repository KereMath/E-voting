#ifndef AGGREGATE_H
#define AGGREGATE_H

#include "setup.h"
#include "keygen.h"   // MasterVerKey tanımlı
#include "unblindsign.h"
#include <vector>
#include <string>
#include <gmp.h>

/*
  AggregateSignature: Nihai aggregate imza σ = (h, s)
  ve debug alanında hesaplama detaylarını saklar.
*/
struct AggregateSignature {
    element_t h;           // Tüm partial imzaların h değeri (aynı kabul edilir)
    element_t s;           // Her partial imzanın s_m değerlerinin, Lagrange katsayılarıyla üssel alınarak çarpımından elde edilen s
    std::string debug_info; // Hesaplama sırasında toplanan debug çıktıları (admin ID’leri, λ değerleri vb.)
};

/*
  aggregateSign: Her seçmenin unblind edilmiş imza parçalarını (with admin ID bilgisiyle) aggregate eder.
  
  Girdi:
    - params: TIAC parametreleri.
    - partialSigsWithAdmins: Her seçmenin unblind edilmiş imza parçalarını içeren vector<pair<Admin ID, UnblindSignature>>
    - mvk: Master verification key (mvk = (α₂, β₂, β₁)); burada mvk.vkm1 = α₂, mvk.vkm2 = β₂ kullanılacak.
    - didStr: Seçmenin DID (hex string).
    - groupOrder: Grup mertebesi (p) (mpz_t).
    
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

/*
  computeLagrangeCoefficient: Verilen admin ID’lerine göre Lagrange katsayısını hesaplar.
  
  Girdi:
    - outCoeff: Çıktı olarak hesaplanan katsayı (Zr tipi element).
    - allIDs: Partial imza üreten admin ID’lerini içeren vektör.
    - idx: Hangi partial imza için katsayı hesaplanıyor (0-tabanlı indeks).
    - groupOrder: Grup mertebesi p (mpz_t).
    - pairing: PBC pairing (Zr elemanları için).
  
  Katsayı, ∏{j ≠ i} (id_j/(id_j - id_i)) mod p şeklinde hesaplanır.
*/
void computeLagrangeCoefficient(element_t outCoeff, const std::vector<int> &allIDs, size_t idx, const mpz_t groupOrder, pairing_t pairing);

#endif
