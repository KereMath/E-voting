#ifndef AGGREGATE_H
#define AGGREGATE_H

#include "setup.h"
#include "keygen.h"
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
  aggregateSign: Her seçmenin unblind edilmiş imza parçalarını (partialSigs)
  EA authority’nin mvk (mvk = (vkm1, vkm2, vkm3)) ve DID kullanarak birleştirir.
  
  Girdi:
    - params: TIAC parametreleri
    - partialSigs: Her seçmenin unblind edilmiş imza parçaları (vector<UnblindSignature>)
    - mvk: TTP tarafından üretilen mvk (mvk.alpha2, mvk.beta2, mvk.beta1); 
           burada mvk.vkm1 = α₂ ve mvk.vkm2 = β₂ olarak kullanılacaktır.
    - didStr: Seçmenin DID (hex string)
  Çıktı:
    - AggregateSignature: Nihai aggregate imza σ = (h, s)
*/
AggregateSignature aggregateSign(
    TIACParams &params,
    const std::vector<UnblindSignature> &partialSigs,
    EAKey &mvk,
    const std::string &didStr
);

#endif
