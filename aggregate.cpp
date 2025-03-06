#include "aggregate.h"
#include <vector>
#include <sstream>
#include <iomanip>
#include <stdexcept>
#include <iostream>
#include <gmp.h>
#include <pbc/pbc.h>

// External function declaration (e.g., from unblindsign.h)
std::string elementToStringG1(element_t elem);

// Helper to cast away const-ness
static inline element_s* toNonConst(const element_s* in) {
    return const_cast<element_s*>(in);
}

// Corrected Lagrange coefficient calculation
void computeLagrangeCoefficient(element_t outCoeff, const std::vector<int> &allIDs, size_t idx, const mpz_t groupOrder, pairing_t pairing) {
    element_set1(outCoeff);
    mpz_t num, den, invDen, tmp;
    mpz_inits(num, den, invDen, tmp, NULL);
    int id_i = allIDs[idx];
    for (size_t j = 0; j < allIDs.size(); j++) {
        if (j == idx) continue;
        int id_j = allIDs[j];
        mpz_set_si(num, id_j);
        mpz_mod(num, num, groupOrder);
        mpz_set_si(den, id_j - id_i);
        mpz_mod(den, den, groupOrder);
        if (mpz_invert(invDen, den, groupOrder) == 0) {
            mpz_clears(num, den, invDen, tmp, NULL);
            throw std::runtime_error("Lagrange inversion failed");
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

    // Initialize h from the first partial signature
    element_init_G1(aggSig.h, params.pairing);
    element_set(aggSig.h, toNonConst(&partialSigsWithAdmins[0].second.h[0]));

    // Initialize s to identity in G1
    element_init_G1(aggSig.s, params.pairing);
    element_set1(aggSig.s);

    std::vector<int> allIDs;
    for (const auto& sig : partialSigsWithAdmins) {
        allIDs.push_back(sig.first);
    }

    for (size_t i = 0; i < partialSigsWithAdmins.size(); ++i) {
        int adminID = partialSigsWithAdmins[i].first;
        element_t lambda;
        element_init_Zr(lambda, params.pairing);
        computeLagrangeCoefficient(lambda, allIDs, i, groupOrder, params.pairing);

        // Compute s_m * lambda (scalar multiplication in G1)
        element_t s_m_exp;
        element_init_G1(s_m_exp, params.pairing);
        element_mul_zn(s_m_exp, toNonConst(&partialSigsWithAdmins[i].second.s_m[0]), lambda);

        element_mul(aggSig.s, aggSig.s, s_m_exp);

        element_clear(lambda);
        element_clear(s_m_exp);
    }

    aggSig.debug_info = debugStream.str();
    return aggSig;
}