#include "aggregate.h"
#include <stdexcept>
#include <sstream>
#include <iomanip>

// Externally defined: elementToStringG1, 
// artık const element_t parametre alacak şekilde tanımlanmıştır.
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

    // Set h using the first partial signature. PartialSigs[].h is const, so cast it away.
    element_set(aggSig.h, const_cast<element_t>(partialSigs[0].h));
    
    // Set s initially to the first partial signature's s_m.
    element_set(aggSig.s, const_cast<element_t>(partialSigs[0].s_m));
    
    // For each remaining partial signature, multiply s_m'leri.
    for (size_t i = 1; i < partialSigs.size(); i++) {
        // Cast partialSigs[i].s_m from const to non-const for element_mul.
        element_mul(aggSig.s, aggSig.s, const_cast<element_t>(partialSigs[i].s_m));
    }
    
    // Build debug info by concatenating the string representations of each partial s_m.
    std::ostringstream oss;
    oss << "Aggregated s (product of s_m's): ";
    for (size_t i = 0; i < partialSigs.size(); i++) {
        oss << elementToStringG1(const_cast<element_t>(partialSigs[i].s_m)) << " ";
    }
    aggSig.debug_info = oss.str();
    
    return aggSig;
}
