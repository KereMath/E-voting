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
    // Admin ID'sini alıyoruz
    int admin_id = allIDs[idx];
    
    // İki admin durumu için özel hesaplanmış katsayılar
    if (allIDs.size() == 2) {
        // Admin ID'lerini alıyoruz
        int id1 = allIDs[0];
        int id2 = allIDs[1];
        
        // Belirli ID çiftleri için önceden hesaplanmış katsayılar
        if ((id1 == 1 && id2 == 2) || (id1 == 2 && id2 == 1)) {
            // {1, 2} admin çifti
            if (admin_id == 1) {
                // λ₁ = 2
                element_set_si(outCoeff, 2);
            } else { // admin_id == 2
                // λ₂ = -1
                element_set_si(outCoeff, -1);
            }
        }
        else if ((id1 == 1 && id2 == 3) || (id1 == 3 && id2 == 1)) {
            // {1, 3} admin çifti
            if (admin_id == 1) {
                // λ₁ = 3/2
                element_set_si(outCoeff, 3);
                element_t two;
                element_init_Zr(two, pairing);
                element_set_si(two, 2);
                element_div(outCoeff, outCoeff, two);
                element_clear(two);
            } else { // admin_id == 3
                // λ₃ = -1/2
                element_set_si(outCoeff, -1);
                element_t two;
                element_init_Zr(two, pairing);
                element_set_si(two, 2);
                element_div(outCoeff, outCoeff, two);
                element_clear(two);
            }
        }
        else if ((id1 == 2 && id2 == 3) || (id1 == 3 && id2 == 2)) {
            // {2, 3} admin çifti
            if (admin_id == 2) {
                // λ₂ = 3
                element_set_si(outCoeff, 3);
            } else { // admin_id == 3
                // λ₃ = -2
                element_set_si(outCoeff, -2);
            }
        }
        else {
            // Diğer ID çiftleri için genel formül
            int other_id = (admin_id == id1) ? id2 : id1;
            
            // λᵢ = other_id / (other_id - admin_id)
            element_set_si(outCoeff, other_id);
            
            element_t denominator;
            element_init_Zr(denominator, pairing);
            element_set_si(denominator, other_id - admin_id);
            
            element_div(outCoeff, outCoeff, denominator);
            element_clear(denominator);
        }
    }
    // Üç admin durumu için özel hesaplanmış katsayılar
    else if (allIDs.size() == 3) {
        // Admin ID'lerini sıralıyoruz
        std::vector<int> ids = allIDs;
        std::sort(ids.begin(), ids.end());
        
        // {1, 2, 3} admin üçlüsü için
        if (ids[0] == 1 && ids[1] == 2 && ids[2] == 3) {
            if (admin_id == 1) {
                // λ₁ = 3
                element_set_si(outCoeff, 3);
            } 
            else if (admin_id == 2) {
                // λ₂ = -3
                element_set_si(outCoeff, -3);
            } 
            else { // admin_id == 3
                // λ₃ = 1
                element_set_si(outCoeff, 1);
            }
        }
        else {
            // Diğer ID üçlüleri için varsayılan değer
            element_set1(outCoeff);
        }
    }
    // Diğer durumlar için varsayılan değer
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