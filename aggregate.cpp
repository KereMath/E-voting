#include "aggregate.h"
#include <openssl/sha.h>
#include <vector>
#include <sstream>
#include <iomanip>
#include <stdexcept>
#include <iostream>

// Helper: mpz_t'yi string'e çevirir.
static std::string mpzToString(const mpz_t value) {
    char* c_str = mpz_get_str(nullptr, 10, value);
    std::string str(c_str);
    free(c_str);
    return str;
}

// Aggregate aşamasında GT elemanlarını hex string'e çeviren yardımcı fonksiyon.
static std::string gtToString(element_t gt_elem) {
    int len = element_length_in_bytes(gt_elem);
    std::vector<unsigned char> buf(len);
    element_to_bytes(buf.data(), gt_elem);
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (auto c : buf)
        oss << std::setw(2) << (int)c;
    return oss.str();
}

AggregateSignature aggregateSign(
    TIACParams &params,
    const std::vector<UnblindSignature> &partialSigs,
    EAKey &mvk,
    const std::string &didStr
) {
    AggregateSignature aggSig;
    std::ostringstream debugStream;
    
    // (1) h: Tüm parçalarda h aynı, ilk parça üzerinden alıyoruz.
    element_init_G1(aggSig.h, params.pairing);
    element_set(aggSig.h, partialSigs[0].h);
    debugStream << "Aggregate h set from first partial signature.\n";
    
    // (2) s: Başlangıçta grup birim elemanı (identity) olarak ayarlanır.
    element_init_G1(aggSig.s, params.pairing);
    element_set1(aggSig.s);  // identity elemanı
    debugStream << "Initial aggregate s set to identity.\n";
    
    // (3) Tüm unblind edilmiş imza parçalarını (s_m) çarparak aggregate s'yi hesapla.
    for (size_t i = 0; i < partialSigs.size(); i++) {
        std::string part = elementToStringG1(partialSigs[i].s_m);
        debugStream << "Multiplying with partial signature " << (i+1)
                    << " s_m = " << part << "\n";
        element_mul(aggSig.s, aggSig.s, partialSigs[i].s_m);
    }
    debugStream << "Aggregate s computed = " << elementToStringG1(aggSig.s) << "\n";
    
    // (4) Pairing kontrolü:
    // Hesaplamak için: e(h, vkm1 * (vkm2)^(DID)) ?= e(s, g2)
    // vkm1 ve vkm2, mvk'nin bileşenleridir.
    mpz_t didInt;
    mpz_init(didInt);
    // DID'i mpz_t'ye çeviriyoruz (aynı didStringToMpz fonksiyonu kullanılabilir)
    if(mpz_set_str(didInt, didStr.c_str(), 16) != 0)
        throw std::runtime_error("aggregateSign: Invalid DID hex string");
    mpz_mod(didInt, didInt, params.prime_order);
    debugStream << "DID (mpz): " << mpzToString(didInt) << "\n";
    
    // (vkm2)^(didInt)
    element_t beta_exp;
    element_init_G1(beta_exp, params.pairing);
    element_t expElement;
    element_init_Zr(expElement, params.pairing);
    element_set_mpz(expElement, didInt);
    element_pow_zn(beta_exp, mvk.vkm2, expElement);
    element_clear(expElement);
    
    // multiplier = vkm1 * beta_exp, where vkm1 = α₂
    element_t multiplier;
    element_init_G1(multiplier, params.pairing);
    element_mul(multiplier, mvk.vkm1, beta_exp);
    element_clear(beta_exp);
    debugStream << "Multiplier (vkm1 * (vkm2)^(DID)) = " << elementToStringG1(multiplier) << "\n";
    
    // Pairing LHS = e(h, multiplier)
    element_t pairing_lhs, pairing_rhs;
    element_init_GT(pairing_lhs, params.pairing);
    element_init_GT(pairing_rhs, params.pairing);
    pairing_apply(pairing_lhs, aggSig.h, multiplier, params.pairing);
    debugStream << "Pairing LHS computed = " << gtToString(pairing_lhs) << "\n";
    element_clear(multiplier);
    
    // Pairing RHS = e(s, g2)
    pairing_apply(pairing_rhs, aggSig.s, params.g2, params.pairing);
    debugStream << "Pairing RHS computed = " << gtToString(pairing_rhs) << "\n";
    
    bool pairing_ok = (element_cmp(pairing_lhs, pairing_rhs) == 0);
    if(!pairing_ok)
        throw std::runtime_error("aggregateSign: Pairing check failed");
    debugStream << "Pairing check PASSED.\n";
    
    element_clear(pairing_lhs);
    element_clear(pairing_rhs);
    mpz_clear(didInt);
    
    aggSig.debug_info = debugStream.str();
    return aggSig;
}
