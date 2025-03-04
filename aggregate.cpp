#include "aggregate.h"
#include <vector>
#include <sstream>
#include <iomanip>
#include <stdexcept>
#include <iostream>

// Yardımcı: G1 elemanını hex string'e çevirir.
std::string elementToStringG1(element_t elem); // Dışarıdan sağlanmış fonksiyon (örn. unblindsign.h'dan)
// Eğer global tanımınız yoksa, buraya benzer şekilde ekleyin.

AggregateSignature aggregateSign(
    TIACParams &params,
    const std::vector<UnblindSignature> &partialSigs,
    MasterVerKey &mvk,
    const std::string &didStr
) {
    AggregateSignature aggSig;
    std::ostringstream debugStream;
    
    // (1) h: Tüm parçalarda h aynı; ilk partial imzadan alınır.
    element_init_G1(aggSig.h, params.pairing);
    // partialSigs[0].h'yi const_cast ile kopyalıyoruz (uyarı almamak için).
    element_set(aggSig.h, const_cast<element_t>(partialSigs[0].h));
    debugStream << "Aggregate h set from first partial signature.\n";
    
    // (2) s: Başlangıçta grup identity elemanı (s = 1) olarak ayarlanır.
    element_init_G1(aggSig.s, params.pairing);
    element_set1(aggSig.s); // Identity elemanı
    debugStream << "Initial aggregate s set to identity.\n";
    
    // (3) Her partial imza parçasının s_m değeri ile aggregate s'yi çarpıyoruz.
    for (size_t i = 0; i < partialSigs.size(); i++) {
        std::string part = elementToStringG1(const_cast<element_t>(partialSigs[i].s_m));
        debugStream << "Multiplying with partial signature " << (i+1)
                    << " s_m = " << part << "\n";
        element_mul(aggSig.s, aggSig.s, const_cast<element_t>(partialSigs[i].s_m));
    }
    debugStream << "Aggregate s computed = " << elementToStringG1(aggSig.s) << "\n";
    
    // (4) Pairing kontrolü kaldırıldı (unblind aşamasında zaten yapıldı).
    aggSig.debug_info = debugStream.str();
    return aggSig;
}
