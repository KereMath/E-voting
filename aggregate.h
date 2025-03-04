#ifndef AGGREGATE_H
#define AGGREGATE_H

#include "setup.h"
#include "keygen.h"   // MasterVerKey tanımlı
#include "unblindsign.h"
#include <vector>
#include <string>

/*
  AggregateSignature: Nihai aggregate imza σ = (h, s)
  ve debug alanında hesaplama detaylarını saklar.
*/
struct AggregateSignature {
    element_t h; // Blind imzadan alınan h (tüm parçalar aynı)
    element_t s; // Unblind edilmiş imza parçalarının çarpımından elde edilen s
    std::string debug_info; // Hesaplama sırasında toplanan debug çıktıları
};

/*
  aggregateSign: Her seçmenin unblind edilmiş imza parçalarını aggregate eder.
  
  Girdi:
    - params: TIAC parametreleri
    - partialSigs: Her seçmenin unblind edilmiş imza parçaları (vector<UnblindSignature>)
    - mvk: Master verification key (mvk = (α₂, β₂, β₁)), burada
           mvk.vkm1 = α₂, mvk.vkm2 = β₂ (kullanılacak)
    - didStr: Seçmenin DID (hex string)
  Çıktı:
    - AggregateSignature: Nihai aggregate imza σ = (h, s) ve debug bilgileri
*/
AggregateSignature aggregateSign(
    TIACParams &params,
    const std::vector<UnblindSignature> &partialSigs,
    MasterVerKey &mvk,
    const std::string &didStr
);

#endif
