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
    element_t h; // Unblind aşamasında tüm parçalarda ortak h
    element_t s; // Unblind imza parçalarının çarpımından elde edilen aggregate s
    std::string debug_info; // Hesaplama sırasında toplanan debug çıktıları
};

/*
  aggregateSign: Her seçmenin unblind edilmiş imza parçalarını aggregate eder.
  
  Girdi:
    - params: TIAC parametreleri
    - partialSigs: Her seçmenin unblind edilmiş imza parçaları (vector<UnblindSignature>)
    - mvk: Master verification key (mvk = (vkm1, vkm2, vkm3)); 
           burada vkm1 ve vkm2 pairing kontrolü için kullanılabilir ama burada kullanılmayacak.
    - didStr: Seçmenin DID (hex string) (Aggregate aşamasında kullanılmayacak)
  Çıktı:
    - AggregateSignature: Nihai aggregate imza σ = (h, s) ve debug bilgileri
       (Bu aşamada pairing kontrolü yapılmadan sadece s parçası hesaplanır.)
*/
AggregateSignature aggregateSign(
    TIACParams &params,
    const std::vector<UnblindSignature> &partialSigs,
    MasterVerKey &mvk,
    const std::string &didStr
);

#endif
