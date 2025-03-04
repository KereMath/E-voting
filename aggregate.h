#ifndef AGGREGATE_H
#define AGGREGATE_H

#include "setup.h"
#include "unblindsign.h"  // UnblindSignature tanımını içerir.
#include "keygen.h"       // MasterVerKey tanımını içerir.
#include <string>
#include <vector>

struct AggregateSignature {
    element_t h; // Aggregate h değeri (partial imzaların h değerlerinin birleşimi)
    element_t s; // Aggregate s değeri (partial imza parçalarının çarpımı)
    std::string debug_info; // Debug bilgileri
};

/**
 * @brief Verilen unblind imza parçalarını (partial signatures) çarparak aggregate imza oluşturur.
 * 
 * @param params TIAC parametreleri.
 * @param partialSigs Her seçmenin unblind imza parçaları.
 * @param mvk EA Authority'nin master verification key bileşenleri.
 * @param didStr Seçmenin DID değeri (hex string).
 * @return AggregateSignature 
 */
AggregateSignature aggregateSign(TIACParams &params,
                                   const std::vector<UnblindSignature>& partialSigs,
                                   MasterVerKey &mvk,
                                   const std::string &didStr);

#endif // AGGREGATE_H
