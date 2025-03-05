#include "aggregate.h"
#include <vector>
#include <sstream>
#include <iomanip>
#include <stdexcept>
#include <iostream>

// Yardımcı: G1 elemanını hex string'e çevirir.
// (Bu fonksiyon, örneğin unblindsign.h gibi dosyalardan sağlanabilir.)
std::string elementToStringG1(element_t elem);

// Yardımcı fonksiyon: const element_t'yi (element_s*) non-const pointer'a çevirir.
static element_s* toNonConst(element_t in) {
    return const_cast<element_s*>(in);
}

AggregateSignature aggregateSign(
    TIACParams &params,
    const std::vector<UnblindSignature> &partialSigs,
    MasterVerKey &mvk,
    const std::string &didStr
) {
    AggregateSignature aggSig;
    std::ostringstream debugStream;
    
    // (1) h: Tüm partial imzaların h değeri aynıdır; bu yüzden ilk partial imzadan alınır.
    element_init_G1(aggSig.h, params.pairing);
    element_set(aggSig.h, const_cast<element_s*>(&partialSigs[0].h[0]));
    debugStream << "[AGGREGATE] Aggregate h set from first partial signature.\n";
    
    // (2) s: Aggregate s değeri başlangıçta grup identity (1) olarak ayarlanır.
    element_init_G1(aggSig.s, params.pairing);
    element_set1(aggSig.s);
    debugStream << "[AGGREGATE] Initial aggregate s set to identity.\n";
    
    // (3) Tüm partial imzaların s_m değerleri, aggregate s ile sırasıyla çarpılır.
    debugStream << "[AGGREGATE] Aggregating partial signatures (indices): ";
    for (size_t i = 0; i < partialSigs.size(); i++) {
        debugStream << (i+1) << " ";
    }
    debugStream << "\n";
    for (size_t i = 0; i < partialSigs.size(); i++) {
        std::string part = elementToStringG1(const_cast<element_s*>(&partialSigs[i].s_m[0]));
        debugStream << "[AGGREGATE] Multiplying with partial signature " << (i+1)
                    << " s_m = " << part << "\n";
        element_mul(aggSig.s, aggSig.s, const_cast<element_s*>(&partialSigs[i].s_m[0]));
    }
    debugStream << "[AGGREGATE] Aggregate s computed = " << elementToStringG1(aggSig.s) << "\n";
    
    // (4) Pairing kontrolü bu aşamada yapılmıyor.
    aggSig.debug_info = debugStream.str();
    return aggSig;
}
