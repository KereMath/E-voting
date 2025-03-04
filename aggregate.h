#ifndef AGGREGATE_H
#define AGGREGATE_H

#include "setup.h"
#include "unblindsign.h"  // UnblindSignature tanımı içeriyor.
#include <string>
#include <vector>

// AggregateSignature: Aggregate imza: σ = (h, s)
struct AggregateSignature {
    element_t h; // Her partial imzadan alınan h (aynı h olmalıdır)
    element_t s; // Partial imza s_m'lerinin çarpımı
    std::string debug_info; // Debug için üretilen ara değerlerin string gösterimi
};

// aggregateSign: Her seçmenin unblind edilmiş imza parçalarının çarpımıyla aggregate imza üretir.
AggregateSignature aggregateSign(TIACParams &params,
                                   const std::vector<UnblindSignature>& partialSigs,
                                   MasterVerKey &mvk,
                                   const std::string &didStr);

#endif
