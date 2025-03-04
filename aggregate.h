#ifndef AGGREGATE_H
#define AGGREGATE_H

#include "setup.h"
#include "unblindsign.h"  // UnblindSignature tanımını içerir.
#include "keygen.h"       // MasterVerKey tanımını içerir.
#include <string>
#include <vector>

struct AggregateSignature {
    element_t h; // Toplanan h değeri
    element_t s; // Toplanan s değeri (partial imza parçalarının çarpımı)
    std::string debug_info; // Debug bilgisi (örneğin, hangi parçaların çarpımı)
};

/**
 * @brief Verilen unblind imza parçalarını (partial signatures) çarparak tek aggregate imza oluşturur.
 * 
 * @param params TIAC parametreleri.
 * @param partialSigs Her seçmenin unblind imza parçaları (UnblindSignature) vektörü.
 * @param mvk EA Authority'nin master verification key bileşenleri (MasterVerKey).
 * @param didStr Seçmenin DID değeri (hex string).
 * @return AggregateSignature 
 */
AggregateSignature aggregateSign(TIACParams &params,
                                   const std::vector<UnblindSignature>& partialSigs,
                                   MasterVerKey &mvk,
                                   const std::string &didStr);

#endif // AGGREGATE_H
