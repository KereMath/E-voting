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

// Helper: const element_t (yani const element_s[1])'nin ilk elemanının adresini non-const pointer olarak döndürür.
static inline element_s* toNonConst(const element_s in[1]) {
    return const_cast<element_s*>(in);
}

// Lagrange katsayısını hesaplar:
// outCoeff = ∏_{j≠i} (id_j/(id_j - id_i)) mod p
void computeLagrangeCoefficient(element_t outCoeff, const std::vector<int> &allIDs, size_t idx, const mpz_t groupOrder, pairing_t pairing) {
    element_set1(outCoeff); // outCoeff = 1
    mpz_t num, den, invDen, tmp;
    mpz_inits(num, den, invDen, tmp, NULL);
    int id_i = allIDs[idx];
    for (size_t j = 0; j < allIDs.size(); j++) {
        if(j == idx) continue;
        int id_j = allIDs[j];
        mpz_set_si(num, id_j);
        mpz_mod(num, num, groupOrder);
        mpz_set_si(den, id_j - id_i);
        mpz_mod(den, den, groupOrder);
        if(mpz_invert(invDen, den, groupOrder) == 0) {
            throw std::runtime_error("computeLagrangeCoefficient: mpz_invert() failed");
        }
        mpz_mul(tmp, num, invDen);
        mpz_mod(tmp, tmp, groupOrder);
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
    element_set(aggSig.h, toNonConst(partialSigsWithAdmins[0].second.h));
    debugStream << "Aggregate h set from first partial signature.\n";
    
    // (2) s: Aggregate s başlangıçta identity (1) olarak ayarlanır.
    element_init_G1(aggSig.s, params.pairing);
    element_set1(aggSig.s);
    debugStream << "Initial aggregate s set to identity.\n";
    
    // Tüm admin ID’lerini toplayalım.
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
                    
        // s_m^(λ) hesapla.
        element_t s_m_exp;
        element_init_G1(s_m_exp, params.pairing);
        element_pow_zn(s_m_exp, toNonConst(partialSigsWithAdmins[i].second.s_m), lambda);
        
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
