#include "aggregate.h"
#include <vector>
#include <sstream>
#include <iomanip>
#include <stdexcept>
#include <iostream>

// Dışarıdan sağlanan fonksiyon: elementToStringG1 (örn. unblindsign.h'dan)
std::string elementToStringG1(element_t elem);

// (İsteğe bağlı) Yardımcı fonksiyon: const element_t'yi non-const pointer'a çevirmek için
// Bu fonksiyon, C tarzı dönüşümle yapılıyor.
static element_s* toNonConst(element_t in) {
    return const_cast<element_s*>(in);
}

AggregateSignature aggregateSign(
    TIACParams &params,
    const std::vector<std::pair<int, UnblindSignature>> &partialSigsWithAdmins,
    MasterVerKey &mvk,
    const std::string &didStr
) {
    AggregateSignature aggSig;
    std::ostringstream debugStream;
    
    // (1) h: Tüm parçalarda h aynı kabul edildiğinden, ilk partial imzadan h alınır.
    element_init_G1(aggSig.h, params.pairing);
    // C tarzı dönüşüm ile constluğu kaldırıyoruz.
    element_set(aggSig.h, (element_t) partialSigsWithAdmins[0].second.h);
    debugStream << "Aggregate h set from first partial signature.\n";
    
    // (2) s: Başlangıçta aggregate s, grup identity elemanı (s = 1) olarak ayarlanır.
    element_init_G1(aggSig.s, params.pairing);
    element_set1(aggSig.s);  // Identity elemanı
    debugStream << "Initial aggregate s set to identity.\n";
    
    // (3) Her partial imza parçasının s_m değeri ile aggregate s'yi çarparız.
    // Aynı zamanda hangi adminin ürettiği de loglanır.
    debugStream << "Combining partial signatures:\n";
    for (size_t i = 0; i < partialSigsWithAdmins.size(); i++) {
        int adminID = partialSigsWithAdmins[i].first;  // Admin ID'si
        // s_m değerini string olarak alalım:
        std::string partStr = elementToStringG1((element_t) partialSigsWithAdmins[i].second.s_m);
        debugStream << "  Partial signature " << (i+1)
                    << " produced by Admin " << (adminID + 1)
                    << ": s_m = " << partStr << "\n";
        // s_m'nin kopyasını oluşturarak aggregate s ile çarpıyoruz.
        element_t s_m_copy;
        element_init_G1(s_m_copy, params.pairing);
        element_set(s_m_copy, (element_t) partialSigsWithAdmins[i].second.s_m);
        element_mul(aggSig.s, aggSig.s, s_m_copy);
        element_clear(s_m_copy);
    }
    debugStream << "Final aggregate s computed = " << elementToStringG1(aggSig.s) << "\n";
    
    // (4) Debug bilgileri saklanır.
    aggSig.debug_info = debugStream.str();
    return aggSig;
}
