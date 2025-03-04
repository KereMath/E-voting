#include "unblindsign.h"
#include <openssl/sha.h>
#include <vector>
#include <sstream>
#include <iomanip>
#include <stdexcept>
#include <iostream>

// Yardımcı: mpz_t değerini string'e çevirir.
static std::string mpzToString(const mpz_t value) {
    char* c_str = mpz_get_str(nullptr, 10, value);
    std::string str(c_str);
    free(c_str);
    return str;
}

// Global: G1 elemanını hex string'e çevirir.
std::string elementToStringG1(element_t elem) {
    int length = element_length_in_bytes(elem);
    std::vector<unsigned char> buf(length);
    element_to_bytes(buf.data(), elem);
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (auto c : buf)
        oss << std::setw(2) << (int)c;
    return oss.str();
}

// DID string'ini mpz_t'ye çevirir.
static void didStringToMpz(const std::string &didStr, mpz_t rop, const mpz_t p) {
    if(mpz_set_str(rop, didStr.c_str(), 16) != 0)
        throw std::runtime_error("didStringToMpz: invalid hex string");
    mpz_mod(rop, rop, p);
}

// inElem'nin hash'ini G1 elemanına aktarır.
static void hashToG1(element_t outG1, TIACParams &params, element_t inElem) {
    std::string s = elementToStringG1(inElem);
    // std::cout << "[HASH TO G1] Input element (hex): " << s << "\n";
    element_from_hash(outG1, s.data(), s.size());
    std::string outStr = elementToStringG1(outG1);
    // std::cout << "[HASH TO G1] Output element (hex): " << outStr << "\n";
}

// Verilen string'lerin birleşiminden hash hesaplar, sonucu outZr'ye atar.
static void hashToZr(element_t outZr, TIACParams &params, const std::vector<std::string> &elems) {
    std::ostringstream oss;
    for (const auto &s : elems)
        oss << s;
    std::string msg = oss.str();
    // std::cout << "[HASH TO Zr] Input concatenated string: " << msg << "\n";
    unsigned char digest[SHA512_DIGEST_LENGTH];
    SHA512(reinterpret_cast<const unsigned char*>(msg.data()), msg.size(), digest);
    // std::cout << "[HASH TO Zr] SHA512 digest: ";
    for (int i = 0; i < SHA512_DIGEST_LENGTH; i++) {
        // std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)digest[i];
    }
    // std::cout << "\n";
    mpz_t tmp;
    mpz_init(tmp);
    mpz_import(tmp, SHA512_DIGEST_LENGTH, 1, 1, 0, 0, digest);
    mpz_mod(tmp, tmp, params.prime_order);
    element_set_mpz(outZr, tmp);
    std::string outZrStr;
    {
        char* str = mpz_get_str(nullptr, 10, tmp);
        outZrStr = str;
        free(str);
    }
    std::cout << "[HASH TO Zr] Output (as mpz): " << outZrStr << "\n";
    mpz_clear(tmp);
}

/*
  unblindSign implementasyonu (Alg. 13):
  1) Hash(comi) kontrolü: Eğer hash(comi) ≠ h, hata verilir.
  2) sₘ = cm * (β₂)^(–o) hesaplanır.
  3) Pairing kontrolü: e(h, α₂ * (β₂)^(didInt)) ?= e(sₘ, g2)
     (didInt, didStr'den hesaplanır.)
  Her adımda girilen değerler ve hesaplanan ara değerler debug olarak ekrana yazdırılır.
*/
UnblindSignature unblindSign(
    TIACParams &params,
    PrepareBlindSignOutput &bsOut,
    BlindSignature &blindSig,
    EAKey &eaKey,
    const std::string &didStr
) {
    UnblindSignature result;
    
    // std::cout << "\n[UNBLIND] STARTING UNBLINDING PROCESS\n";
    // std::cout << "[UNBLIND] bsOut.comi = " << bsOut.debug.comi << "\n";
    // std::cout << "[UNBLIND] bsOut.h    = " << bsOut.debug.h << "\n";
    // std::cout << "[UNBLIND] bsOut.com  = " << bsOut.debug.com << "\n";
    // std::cout << "[UNBLIND] bsOut.o    = " << mpzToString(bsOut.o) << "\n";
    // std::cout << "[UNBLIND] EA Key vkm2 = " << elementToStringG1(eaKey.vkm2) << "\n";
    // std::cout << "[UNBLIND] EA Key vkm1 = " << elementToStringG1(eaKey.vkm1) << "\n";
    
    // (a) h değeri: blind imzadan alınan h
    element_init_G1(result.h, params.pairing);
    element_set(result.h, blindSig.h);
    // std::cout << "[UNBLIND] Result h = " << elementToStringG1(result.h) << "\n";
    
    // (1) Hash(comi) kontrolü:
    element_t h_check;
    element_init_G1(h_check, params.pairing);
    hashToG1(h_check, params, bsOut.comi);
    result.debug.hash_comi = elementToStringG1(h_check);
    // std::cout << "[UNBLIND DEBUG] Hash(comi) computed = " << result.debug.hash_comi << "\n";
    // std::cout << "[UNBLIND DEBUG] bsOut.h              = " << elementToStringG1(bsOut.h) << "\n";
    if(element_cmp(h_check, bsOut.h) != 0) {
        element_clear(h_check);
        throw std::runtime_error("unblindSign: Hash(comi) != h");
    }
    element_clear(h_check);
    
    // (2) sₘ = cm * (β₂)^(–o)
    mpz_t neg_o;
mpz_init(neg_o);
mpz_neg(neg_o, bsOut.o);
mpz_mod(neg_o, neg_o, params.prime_order);
// std::cout << "[UNBLIND DEBUG] Negative o (mpz): " << mpzToString(neg_o) << "\n";

// Zr tipi element oluştur, neg_o'yu atayalım.
element_t exponent;
element_init_Zr(exponent, params.pairing);
element_set_mpz(exponent, neg_o);
// std::cout << "[UNBLIND DEBUG] Exponent (from -o): (converted from mpz value)\n";
mpz_clear(neg_o);

element_t beta_pow;
element_init_G1(beta_pow, params.pairing);
// Eski kodda: element_pow_zn(beta_pow, eaKey.vkm2, exponent);
// Şimdi, istenen düzeltmeye göre vkm3 kullanılacaktır:
element_pow_zn(beta_pow, eaKey.vkm3, exponent);
// std::cout << "[UNBLIND DEBUG] beta_pow (from vkm3) = " << elementToStringG1(beta_pow) << "\n";
element_clear(exponent);

element_init_G1(result.s_m, params.pairing);
element_mul(result.s_m, blindSig.cm, beta_pow);
result.debug.computed_s_m = elementToStringG1(result.s_m);
// std::cout << "[UNBLIND DEBUG] Computed s_m = " << result.debug.computed_s_m << "\n";
element_clear(beta_pow);
    
    // (3) Pairing kontrolü:
    // DID string'inden mpz_t didInt hesaplanır.
    mpz_t didInt;
    mpz_init(didInt);
    didStringToMpz(didStr, didInt, params.prime_order);
    // std::cout << "[UNBLIND DEBUG] didInt = " << mpzToString(didInt) << "\n";
    
    // Exponent oluştur: didInt (Zr tipi)
    element_init_Zr(exponent, params.pairing);
    element_set_mpz(exponent, didInt);
    mpz_clear(didInt);
    // std::cout << "[UNBLIND DEBUG] Exponent for DID (from didInt)\n";
    
    element_t beta_did;
    element_init_G1(beta_did, params.pairing);
    element_pow_zn(beta_did, eaKey.vkm2, exponent);
    // std::cout << "[UNBLIND DEBUG] beta_did = " << elementToStringG1(beta_did) << "\n";
    element_clear(exponent);
    
    // multiplier = α₂ * beta_did, burada α₂ = eaKey.vkm1
    element_t multiplier;
    element_init_G1(multiplier, params.pairing);
    element_mul(multiplier, eaKey.vkm1, beta_did);
    // std::cout << "[UNBLIND DEBUG] Multiplier (α₂ * beta_did) = " << elementToStringG1(multiplier) << "\n";
    element_clear(beta_did);
    
    // Pairing hesaplamaları:
    element_t pairing_lhs, pairing_rhs;
    element_init_GT(pairing_lhs, params.pairing);
    element_init_GT(pairing_rhs, params.pairing);
    pairing_apply(pairing_lhs, result.h, multiplier, params.pairing);
    // std::cout << "[UNBLIND DEBUG] Pairing LHS computed: " << elementToStringG1(pairing_lhs) << "\n";
    element_clear(multiplier);
    pairing_apply(pairing_rhs, result.s_m, params.g2, params.pairing);
    // std::cout << "[UNBLIND DEBUG] Pairing RHS computed: " << elementToStringG1(pairing_rhs) << "\n";
    
    // GT elemanlarını string'e çevirmek için:
    auto gtToString = [&params](element_t gt_elem) -> std::string {
        int len = element_length_in_bytes(gt_elem);
        std::vector<unsigned char> buf(len);
        element_to_bytes(buf.data(), gt_elem);
        std::ostringstream oss;
        oss << std::hex << std::setfill('0');
        for (auto c : buf)
            oss << std::setw(2) << (int)c;
        return oss.str();
    };
    result.debug.pairing_lhs = gtToString(pairing_lhs);
    result.debug.pairing_rhs = gtToString(pairing_rhs);
    // std::cout << "[UNBLIND DEBUG] pairing_lhs (GT) = " << result.debug.pairing_lhs << "\n";
    // std::cout << "[UNBLIND DEBUG] pairing_rhs (GT) = " << result.debug.pairing_rhs << "\n";
    
    bool pairing_ok = (element_cmp(pairing_lhs, pairing_rhs) == 0);
    element_clear(pairing_lhs);
    element_clear(pairing_rhs);
    if(!pairing_ok) {
        throw std::runtime_error("unblindSign: Pairing check failed");
    }
    std::cout << "[UNBLIND DEBUG] Pairing check PASSED\n";
    
    return result;
}
