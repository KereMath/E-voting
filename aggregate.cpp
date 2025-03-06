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

// Yardımcı: const element_t'yi non-const element_s*'ye çevirir.
static element_s* toNonConst(element_t in) {
    return const_cast<element_s*>(in);
}

// Lagrange katsayısını hesaplayan fonksiyon.
// allIDs: Partial imzaları üreten admin ID’lerini içeren vektör.
// idx: Hangi partial imza için katsayı hesaplanıyor (0 tabanlı).
// groupOrder: Grubun mertebesi p (mpz_t)
// pairing: PBC pairing (Zr elemanlarının oluşturulması için)
static void computeLagrangeCoefficient(element_t outCoeff, const std::vector<int> &allIDs, size_t idx, const mpz_t groupOrder, pairing_t pairing) {
    // outCoeff başlangıçta 1 olarak ayarlanır.
    element_set1(outCoeff);

    mpz_t num, den, invDen, tmp;
    mpz_inits(num, den, invDen, tmp, NULL);

    int id_i = allIDs[idx]; // Bu partial imzayı üreten adminin ID'si

    for (size_t j = 0; j < allIDs.size(); j++) {
        if (j == idx) continue;
        int id_j = allIDs[j];

        // num = id_j (örneğin; formül sisteminize göre değişebilir)
        mpz_set_si(num, id_j);
        mpz_mod(num, num, groupOrder);

        // den = (id_j - id_i) mod groupOrder
        mpz_set_si(den, id_j - id_i);
        mpz_mod(den, den, groupOrder);

        if (mpz_invert(invDen, den, groupOrder) == 0) {
            throw std::runtime_error("computeLagrangeCoefficient: mpz_invert() failed");
        }

        // ratio = (num * invDen) mod groupOrder
        mpz_mul(tmp, num, invDen);
        mpz_mod(tmp, tmp, groupOrder);

        // Convert tmp to a Zr element and multiply outCoeff by it.
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

    // (1) h: Partial imzaların hepsinin h değeri aynı kabul edildiğinden, ilk partial imzadan alınır.
    element_init_G1(aggSig.h, params.pairing);
    element_set(aggSig.h, toNonConst(partialSigsWithAdmins[0].second.h));
    debugStream << "Aggregate h set from first partial signature.\n";

    // (2) s: Başlangıçta aggregate s, grup identity elemanı (1) olarak ayarlanır.
    element_init_G1(aggSig.s, params.pairing);
    element_set1(aggSig.s);
    debugStream << "Initial aggregate s set to identity.\n";

    // Tüm admin ID’lerini toplayalım:
    std::vector<int> allIDs;
    for (size_t i = 0; i < partialSigsWithAdmins.size(); i++) {
        allIDs.push_back(partialSigsWithAdmins[i].first);
    }

    // (3) Her partial imza için: s_m^(lambda) hesaplanır ve aggregate s ile çarpılır.
    debugStream << "Combining partial signatures with Lagrange coefficients:\n";
    for (size_t i = 0; i < partialSigsWithAdmins.size(); i++) {
        int adminID = partialSigsWithAdmins[i].first;

        // Lagrange katsayısını hesapla:
        element_t lambda;
        element_init_Zr(lambda, params.pairing);
        computeLagrangeCoefficient(lambda, allIDs, i, groupOrder, params.pairing);

        // s_m^(lambda) hesapla:
        element_t s_m_exp;
        element_init_G1(s_m_exp, params.pairing);
        element_pow_zn(s_m_exp, toNonConst(partialSigsWithAdmins[i].second.s_m), lambda);

        // Aggregate s ile çarp:
        element_mul(aggSig.s, aggSig.s, s_m_exp);

        // Debug çıktısı:
        std::string partStr = elementToStringG1(s_m_exp);
        debugStream << "  Partial signature " << (i+1)
                    << " from Admin " << (adminID + 1)
                    << ": s_m^(lambda) = " << partStr << "\n";

        element_clear(lambda);
        element_clear(s_m_exp);
    }
    debugStream << "Final aggregate s computed = " << elementToStringG1(aggSig.s) << "\n";

    // (4) Debug bilgilerini sakla.
    aggSig.debug_info = debugStream.str();
    return aggSig;
}
