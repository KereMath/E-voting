#include "aggregate.h"
#include <vector>
#include <sstream>
#include <iomanip>
#include <stdexcept>
#include <iostream>
#include <gmp.h>
#include <pbc/pbc.h>

// Dışarıdan sağlanan fonksiyon: elementToStringG1 (örn. unblindsign.h'dan)
std::string elementToStringG1(element_t elem);

// Helper: const element_t'yi non-const pointer'a çevirir.
// (Not: element_t aslında element_s[1] tipinde olduğundan, dizinin ilk elemanının adresını kullanıyoruz.)
static element_s* toNonConst(element_t in) {
    return const_cast<element_s*>(&in[0]);
}

void computeLagrangeCoefficient(element_t outCoeff, const std::vector<int> &allIDs, size_t idx, const mpz_t groupOrder, pairing_t pairing) {
    // outCoeff başlangıçta 1 olarak ayarlanır.
    element_set1(outCoeff);

    mpz_t num, den, invDen, tmp;
    mpz_inits(num, den, invDen, tmp, NULL);

    int id_i = allIDs[idx];

    for (size_t j = 0; j < allIDs.size(); j++) {
        if (j == idx) continue;
        int id_j = allIDs[j];

        // num = id_j mod groupOrder
        mpz_set_si(num, id_j);
        mpz_mod(num, num, groupOrder);

        // den = (id_j - id_i) mod groupOrder
        mpz_set_si(den, id_j - id_i);
        mpz_mod(den, den, groupOrder);

        if (mpz_invert(invDen, den, groupOrder) == 0) {
            throw std::runtime_error("computeLagrangeCoefficient: mpz_invert() failed");
        }

        // tmp = (num * invDen) mod groupOrder
        mpz_mul(tmp, num, invDen);
        mpz_mod(tmp, tmp, groupOrder);

        // Convert tmp to a Zr element.
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

    // (1) h: Tüm partial imzaların h değeri aynı kabul edildiğinden, ilk partial imzadan alınır.
    element_init_G1(aggSig.h, params.pairing);
    // partialSigsWithAdmins[0].second.h is an element_t (element_s[1]); bunun ilk elemanının adresini alıyoruz.
    element_set(aggSig.h, const_cast<element_s*>(&(partialSigsWithAdmins[0].second.h[0])));
    debugStream << "Aggregate h set from first partial signature.\n";

    // (2) s: Aggregate s başlangıçta grup identity (1) olarak ayarlanır.
    element_init_G1(aggSig.s, params.pairing);
    element_set1(aggSig.s);
    debugStream << "Initial aggregate s set to identity.\n";

    // Tüm admin ID’lerini toplayalım.
    std::vector<int> allIDs;
    for (size_t i = 0; i < partialSigsWithAdmins.size(); i++) {
        allIDs.push_back(partialSigsWithAdmins[i].first);
    }

    debugStream << "Combining partial signatures with Lagrange coefficients:\n";
    // (3) Her partial imza için:
    for (size_t i = 0; i < partialSigsWithAdmins.size(); i++) {
        int adminID = partialSigsWithAdmins[i].first;
        // Lagrange katsayısını hesapla.
        element_t lambda;
        element_init_Zr(lambda, params.pairing);
        computeLagrangeCoefficient(lambda, allIDs, i, groupOrder, params.pairing);

        // s_m^(lambda) hesapla.
        element_t s_m_exp;
        element_init_G1(s_m_exp, params.pairing);
        element_pow_zn(s_m_exp, const_cast<element_s*>(&(partialSigsWithAdmins[i].second.s_m[0])), lambda);

        // Aggregate s ile çarp.
        element_mul(aggSig.s, aggSig.s, s_m_exp);

        std::string partStr = elementToStringG1(s_m_exp);
        debugStream << "  Partial signature " << (i+1)
                    << " from Admin " << (adminID + 1)
                    << ": s_m^(λ) = " << partStr << "\n";

        element_clear(lambda);
        element_clear(s_m_exp);
    }
    debugStream << "Final aggregate s computed = " << elementToStringG1(aggSig.s) << "\n";

    // (4) Debug bilgilerini sakla.
    aggSig.debug_info = debugStream.str();
    return aggSig;
}
