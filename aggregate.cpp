#include "aggregate.h"
#include <stdexcept>
#include <sstream>
#include <iomanip>

// Extern olarak tanımlı: elementToStringG1 artık const parametre alır.
extern std::string elementToStringG1(const element_t elem);

AggregateSignature aggregateSign(TIACParams &params,
                                   const std::vector<UnblindSignature>& partialSigs,
                                   MasterVerKey &mvk,
                                   const std::string &didStr) {
    if (partialSigs.empty()) {
        throw std::runtime_error("aggregateSign: No partial signatures provided.");
    }
    
    AggregateSignature aggSig;
    // Initialize aggregate signature components:
    element_init_G1(aggSig.h, params.pairing);
    element_init_G1(aggSig.s, params.pairing);

    // partialSigs[i].h ve partialSigs[i].s_m tanımları element_t (yani element_s[1]) olduğundan,
    // bunların pointer’larını almak için &partialSigs[i].h[0] kullanılmalıdır.
    element_set(aggSig.h, &partialSigs[0].h[0]);
    element_set(aggSig.s, &partialSigs[0].s_m[0]);
    
    // Her kalan partial imza parçasının s_m değerini çarparız.
    for (size_t i = 1; i < partialSigs.size(); i++) {
        element_mul(aggSig.s, aggSig.s, &partialSigs[i].s_m[0]);
    }
    
    // Debug bilgisini oluşturmak için s_m değerlerinin string gösterimlerini birleştiriyoruz.
    std::ostringstream oss;
    oss << "Aggregated s (product of s_m's): ";
    for (size_t i = 0; i < partialSigs.size(); i++) {
        oss << elementToStringG1(&partialSigs[i].s_m[0]) << " ";
    }
    aggSig.debug_info = oss.str();
    
    return aggSig;
}
