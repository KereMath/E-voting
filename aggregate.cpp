#include "aggregate.h"
#include <vector>
#include <sstream>
#include <iomanip>
#include <stdexcept>
#include <iostream>

// Dışarıdan sağlanan fonksiyon: elementToStringG1 (örn. unblindsign.h'dan)
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
    
    // (1) h: Tüm parçalarda h aynı kabul edildiğinden, ilk partial imzadan h alınır.
    element_init_G1(aggSig.h, params.pairing);
    // const pointer'ı geçici bir pointer'a dönüştürmeden kullanalım.
    element_set(aggSig.h, partialSigsWithAdmins[0].second.h);
    debugStream << "Aggregate h set from first partial signature.\n";
    
    // (2) s: Başlangıçta aggregate s, grup identity elemanı olarak ayarlanır.
    element_init_G1(aggSig.s, params.pairing);
    element_set1(aggSig.s);  // Identity elemanı
    debugStream << "Initial aggregate s set to identity.\n";
    
    // (3) Her partial imza parçasının s_m değeri ile aggregate s'yi çarparız ve debug loguna admin ID'sini ekleriz.
    debugStream << "Combining partial signatures:\n";
    for (size_t i = 0; i < partialSigsWithAdmins.size(); i++) {
        int adminID = partialSigsWithAdmins[i].first;  // Admin ID'si
        // Element'i string'e çevirelim ve debug için ekleyelim
        std::string partStr = elementToStringG1(partialSigsWithAdmins[i].second.s_m); // s_m değeri alınır.
        debugStream << "  Partial signature " << (i+1)
                    << " produced by Admin " << (adminID + 1)
                    << ": s_m = " << partStr << "\n";
        
        // Burada element_set ve element_mul fonksiyonları const olmayan verilerle işlem yapar.
        element_t s_m_copy;
        element_init_G1(s_m_copy, params.pairing);
        element_set(s_m_copy, partialSigsWithAdmins[i].second.s_m);  // Copy s_m to s_m_copy
        
        element_mul(aggSig.s, aggSig.s, s_m_copy); // s_m çarpımı
        
        element_clear(s_m_copy); // Bellek temizliği
    }
    debugStream << "Final aggregate s computed = " << elementToStringG1(aggSig.s) << "\n";
    
    // (4) Debug bilgileri saklanır.
    aggSig.debug_info = debugStream.str();
    return aggSig;
}
