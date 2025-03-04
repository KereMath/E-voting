#include "aggregate.h"
#include <stdexcept>
#include <sstream>
#include <iomanip>

// elementToStringG1 tanımını dışarıdan alıyoruz (const parametre alacak şekilde)
extern std::string elementToStringG1(const element_t elem);

AggregateSignature aggregateSign(TIACParams &params,
                                   const std::vector<UnblindSignature>& partialSigs,
                                   MasterVerKey &mvk,
                                   const std::string &didStr) {
    if (partialSigs.empty()) {
        throw std::runtime_error("aggregateSign: No partial signatures provided.");
    }
    
    AggregateSignature aggSig;
    element_init_G1(aggSig.h, params.pairing);
    element_set(aggSig.h, partialSigs[0].h);
    
    element_init_G1(aggSig.s, params.pairing);
    element_set(aggSig.s, partialSigs[0].s_m);
    
    // Her partial imza için s_m'leri çarparız.
    for (size_t i = 1; i < partialSigs.size(); i++) {
        element_mul(aggSig.s, aggSig.s, partialSigs[i].s_m);
    }
    
    // Debug bilgisi: her partial s_m'nin string gösterimini birleştirir.
    std::ostringstream oss;
    oss << "Aggregated s (product of s_m's): ";
    for (size_t i = 0; i < partialSigs.size(); i++) {
        oss << elementToStringG1(partialSigs[i].s_m) << " ";
    }
    aggSig.debug_info = oss.str();
    
    return aggSig;
}
