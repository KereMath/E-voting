#include "aggregate.h"
#include <vector>
#include <sstream>
#include <iomanip>
#include <stdexcept>
#include <iostream>

// Dışarıdan sağlanan fonksiyon: elementToStringG1 (örn. unblindsign.h'dan)
std::string elementToStringG1(element_t elem);

// Yardımcı fonksiyon: const element_t (yani const element_s [1])'yi non-const element_s*'ye çevirir.
static element_s* toNonConst(element_t in) {
    // in ifadesi zaten bir dizi olduğundan, dizinin ilk elemanının adresını döndürmek yeterlidir.
    return const_cast<element_s*>(&in[0]);
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
    element_set(aggSig.h, toNonConst(partialSigsWithAdmins[0].second.h));
    debugStream << "Aggregate h set from first partial signature.\n";
    
    // (2) s: Başlangıçta aggregate s, grup identity elemanı olarak ayarlanır.
    element_init_G1(aggSig.s, params.pairing);
    element_set1(aggSig.s);  // Identity elemanı
    debugStream << "Initial aggregate s set to identity.\n";
    
    // (3) Her partial imza parçasının s_m değeri ile aggregate s'yi çarparız ve debug loguna admin ID'sini ekleriz.
    debugStream << "Combining partial signatures:\n";
    for (size_t i = 0; i < partialSigsWithAdmins.size(); i++) {
        int adminID = partialSigsWithAdmins[i].first;  // Admin ID'si
        std::string partStr = elementToStringG1(toNonConst(partialSigsWithAdmins[i].second.s_m));
        debugStream << "  Partial signature " << (i+1)
                    << " produced by Admin " << (adminID + 1)
                    << ": s_m = " << partStr << "\n";
        element_mul(aggSig.s, aggSig.s, toNonConst(partialSigsWithAdmins[i].second.s_m));
    }
    debugStream << "Final aggregate s computed = " << elementToStringG1(aggSig.s) << "\n";
    
    // (4) Debug bilgileri saklanır.
    aggSig.debug_info = debugStream.str();
    return aggSig;
}
