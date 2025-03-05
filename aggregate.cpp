#include "aggregate.h"
#include <vector>
#include <sstream>
#include <iomanip>
#include <stdexcept>
#include <iostream>

// Yardımcı: G1 elemanını hex string'e çevirir.
std::string elementToStringG1(element_t elem);

// aggregateSign fonksiyonu: Her seçmenin unblind edilmiş imza parçalarını aggregate eder.
AggregateSignature aggregateSign(
    TIACParams &params,
    const std::vector<std::pair<int, UnblindSignature>> &partialSigsWithAdmins,
    MasterVerKey &mvk,
    const std::string &didStr
) {
    AggregateSignature aggSig;
    std::ostringstream debugStream;

    // (1) h: İlk partial imzadan h alınır.
    element_init_G1(aggSig.h, params.pairing);
    element_set(aggSig.h, partialSigsWithAdmins[0].second.h);
    debugStream << "Aggregate h set from first partial signature.\n";

    // (2) s: Başlangıçta grup identity elemanı olarak ayarlanır.
    element_init_G1(aggSig.s, params.pairing);
    element_set1(aggSig.s);
    debugStream << "Initial aggregate s set to identity.\n";

    // (3) Partial imza parçalarının s_m değerleri ile aggregate s'yi çarpıyoruz.
    debugStream << "Combining partial signatures:\n";
    for (size_t i = 0; i < partialSigsWithAdmins.size(); i++) {
        int adminID = partialSigsWithAdmins[i].first;  // Admin ID
        std::string partStr = elementToStringG1(partialSigsWithAdmins[i].second.s_m);

        debugStream << "  Partial signature " << (i+1)
                    << " produced by Admin " << (adminID + 1)
                    << ": s_m = " << partStr << "\n";

        element_t s_m_copy;
        element_init_G1(s_m_copy, params.pairing);
        element_set(s_m_copy, partialSigsWithAdmins[i].second.s_m);

        element_mul(aggSig.s, aggSig.s, s_m_copy);
        element_clear(s_m_copy);
    }
    debugStream << "Final aggregate s computed = " << elementToStringG1(aggSig.s) << "\n";

    // Debug bilgileri saklanır.
    aggSig.debug_info = debugStream.str();
    return aggSig;
}
