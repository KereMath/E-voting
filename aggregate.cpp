#include "aggregate.h"
#include <vector>
#include <sstream>
#include <iomanip>
#include <stdexcept>
#include <iostream>
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
    // Belirli admin kombinasyonları için önceden hesaplanmış değerleri kullan
    if (allIDs.size() == 2) {
        // 2 admin için: {1, 2}
        int id_i = allIDs[idx];
        
        if (id_i == 1) {
            // lambda1 = 2 (2 admin için)
            element_set_si(outCoeff, 2);
            return;
        } else if (id_i == 2) {
            // lambda2 = -1 ≡ (p-1) mod p (2 admin için)
            mpz_t p_minus_1;
            mpz_init(p_minus_1);
            mpz_sub_ui(p_minus_1, groupOrder, 1); // p-1
            element_set_mpz(outCoeff, p_minus_1);
            mpz_clear(p_minus_1);
            return;
        }
    } else if (allIDs.size() == 3) {
        // 3 admin için: {1, 2, 3}
        int id_i = allIDs[idx];
        
        if (id_i == 1) {
            // lambda1 = 3 (3 admin için)
            element_set_si(outCoeff, 3);
            return;
        } else if (id_i == 2) {
            // lambda2 = -3 ≡ (p-3) mod p (3 admin için)
            mpz_t p_minus_3;
            mpz_init(p_minus_3);
            mpz_sub_ui(p_minus_3, groupOrder, 3); // p-3
            element_set_mpz(outCoeff, p_minus_3);
            mpz_clear(p_minus_3);
            return;
        } else if (id_i == 3) {
            // lambda3 = 1 (3 admin için)
            element_set1(outCoeff);
            return;
        }
    }
    
    // Genel durum - hesaplama yöntemini kullan
    element_set1(outCoeff); // outCoeff = 1
    mpz_t num, den, invDen, tmp;
    mpz_inits(num, den, invDen, tmp, NULL);
    int id_i = allIDs[idx];
    
    for (size_t j = 0; j < allIDs.size(); j++) {
        if (j == idx) continue;
        int id_j = allIDs[j];
        
        // Numerator: id_j
        mpz_set_si(num, id_j);
        mpz_mod(num, num, groupOrder);
        
        // Denominator: id_j - id_i
        mpz_set_si(den, id_j - id_i);
        
        // Negatif değerler için: -x ≡ p-x (mod p)
        if (mpz_sgn(den) < 0) {
            // den değerini pozitif eşdeğerine dönüştür
            mpz_neg(den, den);               // den = -den
            mpz_mod(den, den, groupOrder);   // den = den mod p
            mpz_sub(den, groupOrder, den);   // den = p - den
        } else {
            mpz_mod(den, den, groupOrder);
        }
        
        // Compute modular inverse of denominator
        if (mpz_invert(invDen, den, groupOrder) == 0) {
            throw std::runtime_error("computeLagrangeCoefficient: mpz_invert() failed");
        }
        
        // Compute id_j * (id_j - id_i)^(-1) mod p
        mpz_mul(tmp, num, invDen);
        mpz_mod(tmp, tmp, groupOrder);
        
        // Convert to element and multiply with outCoeff
        element_t ratio;
        element_init_Zr(ratio, pairing);
        element_set_mpz(ratio, tmp);
        element_mul(outCoeff, outCoeff, ratio);
        element_clear(ratio);
    }
    mpz_clears(num, den, invDen, tmp, NULL);
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