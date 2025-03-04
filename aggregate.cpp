#include "aggregate.h"
#include <stdexcept>
#include <sstream>
#include <iomanip>

// Dışarıdan tanımlı: elementToStringG1 – parametre tipini const olarak alabilir.
extern std::string elementToStringG1(const element_t elem);

AggregateSignature aggregateSign(TIACParams &params,
                                   const std::vector<UnblindSignature>& partialSigs,
                                   MasterVerKey &mvk,
                                   const std::string &didStr) {
    if (partialSigs.empty()) {
        throw std::runtime_error("aggregateSign: No partial signatures provided.");
    }
    
    AggregateSignature aggSig;
    // Aggregate imza bileşenlerini başlatın.
    element_init_G1(aggSig.h, params.pairing);
    element_init_G1(aggSig.s, params.pairing);

    // UnblindSignature yapıdaki element_t (yani element_s[1]) verileri sabit olabilir.
    // Bu nedenle, direkt C stili dönüşüm (cast) kullanarak "non‑const" pointer elde ediyoruz.
    element_set(aggSig.h, (element_t)partialSigs[0].h);
    element_set(aggSig.s, (element_t)partialSigs[0].s_m);
    
    for (size_t i = 1; i < partialSigs.size(); i++) {
        element_mul(aggSig.s, aggSig.s, (element_t)partialSigs[i].s_m);
    }
    
    std::ostringstream oss;
    oss << "Aggregated s (product of s_m's): ";
    for (size_t i = 0; i < partialSigs.size(); i++) {
        oss << elementToStringG1((element_t)partialSigs[i].s_m) << " ";
    }
    aggSig.debug_info = oss.str();
    
    return aggSig;
}
