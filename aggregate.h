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
    element_t h; // Unblind imzadan alınan h (tüm parçalar aynı kabul edilir)
    element_t s; // Her partial imzanın s_m değerlerinin çarpımından elde edilen s
    std::string debug_info; // Hesaplama sırasında toplanan debug çıktıları (admin bilgileri vb.)
};

/*
  aggregateSign: Her seçmenin unblind edilmiş imza parçalarını aggregate eder.
  
  Girdi:
    - params: TIAC parametreleri
    - partialSigsWithAdmins: Her seçmenin unblind edilmiş imza parçalarını içeren 
      vector<pair<Admin ID, UnblindSignature>>
    - mvk: Master verification key (mvk = (α₂, β₂, β₁)); burada
           mvk.vkm1 = α₂, mvk.vkm2 = β₂ (kullanılacak)
    - didStr: Seçmenin DID (hex string)
  Çıktı:
    - AggregateSignature: Nihai aggregate imza σ = (h, s) ve debug bilgileri.
*/
AggregateSignature aggregateSign(
    TIACParams &params,
    const std::vector<std::pair<int, UnblindSignature>> &partialSigsWithAdmins,
    MasterVerKey &mvk,
    const std::string &didStr
);

#endif
