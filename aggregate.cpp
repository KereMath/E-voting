#include "aggregate.h"
#include <vector>
#include <sstream>
#include <iomanip>
#include <stdexcept>
#include <iostream>

// Yardımcı: G1 elemanını hex string'e çevirir.
std::string elementToStringG1(element_t elem); // Dışarıdan sağlanmış fonksiyon (örn. unblindsign.h'dan)
// Eğer global tanımınız yoksa, buraya benzer şekilde ekleyin.

// Yardımcı fonksiyon: element_t (const) verisini non-const pointer'a çevirir.
// Yardımcı fonksiyon: const element_t'yi (yani element_s*) non-const element_s*'ye çevirir.
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
    
    // (1) h: Tüm parçalarda h aynı; ilk partial imzadan alınır.
    element_init_G1(aggSig.h, params.pairing);
    element_set(aggSig.h, const_cast<element_s*>(&partialSigs[0].h[0]));
    debugStream << "[AGGREGATE] Aggregate h set from first partial signature.\n";
    
    // (2) s: Başlangıçta grup identity elemanı (s = 1) olarak ayarlanır.
    element_init_G1(aggSig.s, params.pairing);
    element_set1(aggSig.s);  // Identity elemanı
    debugStream << "[AGGREGATE] Initial aggregate s set to identity.\n";
    
    // (3) Her partial imza parçasının s_m değeri ile aggregate s'yi çarpıyoruz.
    debugStream << "[AGGREGATE] Aggregating partial signatures from admin IDs: ";
    for (size_t i = 0; i < partialSigs.size(); i++) {
        // Her partial imzadan admin ID'sini debug mesajına ekle
        debugStream << partialSigs[i].debug.adminId << " ";
    }
    debugStream << "\n";
    for (size_t i = 0; i < partialSigs.size(); i++) {
        std::string part = elementToStringG1(const_cast<element_s*>(&partialSigs[i].s_m[0]));
        debugStream << "[AGGREGATE] Multiplying with partial signature " << (i+1)
                    << " (admin " << partialSigs[i].debug.adminId << ")"
                    << " s_m = " << part << "\n";
        element_mul(aggSig.s, aggSig.s, const_cast<element_s*>(&partialSigs[i].s_m[0]));
    }
    debugStream << "[AGGREGATE] Aggregate s computed = " << elementToStringG1(aggSig.s) << "\n";
    
    // (4) Pairing kontrolü kaldırıldı.
    aggSig.debug_info = debugStream.str();
    return aggSig;
}
