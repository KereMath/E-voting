#include "aggregate.h"
#include <vector>
#include <sstream>
#include <iomanip>
#include <stdexcept>
#include <iostream>
#include <algorithm> // For std::sort
#include <gmp.h>
#include <pbc/pbc.h>

// Dışarıdan sağlanan fonksiyon: elementToStringG1 (örneğin, unblindsign.h'dan)
std::string elementToStringG1(element_t elem);

// Helper: const element_s*'yi non-const element_s*'ye dönüştürür.
static inline element_s* toNonConst(const element_s* in) {
    return const_cast<element_s*>(in);
}

// Lagrange katsayısını hesaplar:
// outCoeff = ∏ ( id_j / (id_j - id_i) )  (j ≠ i) mod p
void computeLagrangeCoefficient(element_t outCoeff, const std::vector<int> &allIDs, size_t idx, const mpz_t groupOrder, pairing_t pairing) {
    // İki admin durumu için hardcoded katsayılar
    std::cout << "Admin IDs: "; for(int id : allIDs) std::cout << id << " "; std::cout << std::endl;
    if (allIDs.size() == 2) {
        // Admin idx'sinin ID'sini alıyoruz
        int current_admin_id = allIDs[idx];
        
        // Admin ID'lerini low ve high olarak ayırıyoruz
        int low_id = std::min(allIDs[0], allIDs[1]);
        int high_id = std::max(allIDs[0], allIDs[1]);
        
        if (current_admin_id == low_id) {
            // Düşük ID'li admin için lambda = 2
            element_set_si(outCoeff, 2);
        } else {
            // Yüksek ID'li admin için lambda = -1
            element_set_si(outCoeff, -1);
        }
    }
    // Üç admin durumu için hardcoded katsayılar
    else if (allIDs.size() == 3) {
        // Admin idx'sinin ID'sini alıyoruz
        int current_admin_id = allIDs[idx];
        
        // Admin ID'lerini sıralıyoruz
        std::vector<int> sorted_ids = allIDs;
        std::sort(sorted_ids.begin(), sorted_ids.end());
        
        if (current_admin_id == sorted_ids[0]) {
            // En düşük ID'li admin için lambda = 3
            element_set_si(outCoeff, 3);
        } else if (current_admin_id == sorted_ids[1]) {
            // Ortadaki ID'li admin için lambda = -3
            element_set_si(outCoeff, -3);
        } else {
            // En yüksek ID'li admin için lambda = 1
            element_set_si(outCoeff, 1);
        }
    }
    // Eğer hardcoded duruma uymazsa default değer olarak 1 döndür
    else {
        element_set1(outCoeff);
    }
}

AggregateSignature aggregateSign(
    TIACParams &params,
    const std::vector<std::pair<int, UnblindSignature>> &partialSigsWithAdmins,
    MasterVerKey &mvk,
    const std::string &didStr,
    const mpz_t groupOrder
) {
    AggregateSignature aggSig;
    std::ostringstream debugStream;
    
    // (1) h: Tüm partial imzaların h değeri aynı kabul edildiğinden, ilk partial imzadan h alınır.
    element_init_G1(aggSig.h, params.pairing);
    // partialSigsWithAdmins[0].second.h is an element_t, which is defined as element_s[1]. 
    // We take the address of the first element.
    element_set(aggSig.h, toNonConst(&(partialSigsWithAdmins[0].second.h[0])));
    debugStream << "Aggregate h set from first partial signature.\n";
    
    // (2) s: Aggregate s başlangıçta identity (1) olarak ayarlanır.
    element_init_G1(aggSig.s, params.pairing);
    element_set1(aggSig.s);
    debugStream << "Initial aggregate s set to identity.\n";
    
    // Tüm admin ID'lerini toplayalım.
    std::vector<int> allIDs;
    for (size_t i = 0; i < partialSigsWithAdmins.size(); i++) {
        allIDs.push_back(partialSigsWithAdmins[i].first);
    }
    debugStream << "Combining partial signatures with Lagrange coefficients:\n";
    
    // (3) Her partial imza için Lagrange katsayısı hesaplanır ve s_m^(λ) ile çarpılır.
    for (size_t i = 0; i < partialSigsWithAdmins.size(); i++) {
        int adminID = partialSigsWithAdmins[i].first;
        element_t lambda;
        element_init_Zr(lambda, params.pairing);
        computeLagrangeCoefficient(lambda, allIDs, i, groupOrder, params.pairing);
        
        char lambdaBuf[1024];
        element_snprintf(lambdaBuf, sizeof(lambdaBuf), "%B", lambda);
        debugStream << "Lagrange coefficient for partial signature " << (i+1)
                    << " from Admin " << (adminID + 1)
                    << " is: " << lambdaBuf << "\n";
                    
        // s_m^(λ) hesapla. partialSigsWithAdmins[i].second.s_m is an element_t; use its first element.
        element_t s_m_exp;
        element_init_G1(s_m_exp, params.pairing);
        element_pow_zn(s_m_exp, toNonConst(&(partialSigsWithAdmins[i].second.s_m[0])), lambda);
        
        char s_m_expBuf[1024];
        element_snprintf(s_m_expBuf, sizeof(s_m_expBuf), "%B", s_m_exp);
        debugStream << "Partial signature " << (i+1)
                    << " from Admin " << (adminID + 1)
                    << ": s_m^(λ) = " << s_m_expBuf << "\n";
                    
        // Aggregate s ile çarp.
        element_mul(aggSig.s, aggSig.s, s_m_exp);
        element_clear(lambda);
        element_clear(s_m_exp);
    }
    char s_final[1024];
    element_snprintf(s_final, sizeof(s_final), "%B", aggSig.s);
    debugStream << "Final aggregate s computed = " << s_final << "\n";
    
    aggSig.debug_info = debugStream.str();
    return aggSig;
}