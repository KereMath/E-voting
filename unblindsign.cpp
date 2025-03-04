#include "unblindsign.h"
#include <openssl/sha.h>
#include <vector>
#include <sstream>
#include <iomanip>
#include <stdexcept>
#include <iostream>

// Global olarak kullanılacak: G1 elemanını hex string'e çeviren fonksiyon
std::string elementToStringG1(element_t elem) {
    int length = element_length_in_bytes(elem);
    std::vector<unsigned char> buf(length);
    element_to_bytes(buf.data(), elem);
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (auto c : buf) {
        oss << std::setw(2) << (int)c;
    }
    return oss.str();
}

// Yardımcı: DID string'ini mpz_t'ye çevirir.
static void didStringToMpz(const std::string &didStr, mpz_t rop, const mpz_t p) {
    if(mpz_set_str(rop, didStr.c_str(), 16) != 0) {
        throw std::runtime_error("didStringToMpz: invalid hex string");
    }
    mpz_mod(rop, rop, p);
}

// Yardımcı: inElem'nin hash'ini G1 elemanına aktarır.
static void hashToG1(element_t outG1, TIACParams &params, element_t inElem) {
    std::string s = elementToStringG1(inElem);
    element_from_hash(outG1, s.data(), s.size());
}

// Yardımcı: Verilen string'lerin birleşiminden hash hesaplar ve sonucu outZr'ye atar.
static void hashToZr(element_t outZr, TIACParams &params, const std::vector<std::string> &elems) {
    std::ostringstream oss;
    for (const auto &s : elems) {
        oss << s;
    }
    std::string msg = oss.str();
    unsigned char digest[SHA512_DIGEST_LENGTH];
    SHA512(reinterpret_cast<const unsigned char*>(msg.data()), msg.size(), digest);
    mpz_t tmp;
    mpz_init(tmp);
    mpz_import(tmp, SHA512_DIGEST_LENGTH, 1, 1, 0, 0, digest);
    mpz_mod(tmp, tmp, params.prime_order);
    element_set_mpz(outZr, tmp);
    mpz_clear(tmp);
}

/*
  unblindSign implementasyonu (Alg. 13):
  1) Hash(comi) kontrolü: Eğer hash(comi) ≠ h, hata verir.
  2) sₘ = cm · (β₂)^(–o) hesaplanır. (o, prepare aşamasından alınmıştır.)
  3) Pairing kontrolü: e(h, α₂·(β₂)^(didInt)) ?= e(sₘ, g2)
  Her adımda ara sonuçlar ekrana yazdırılır.
*/
UnblindSignature unblindSign(
    TIACParams &params,
    PrepareBlindSignOutput &bsOut,
    BlindSignature &blindSig,
    EAKey &eaKey,
    const std::string &didStr
) {
    UnblindSignature result;
    
    // (a) h değeri: blind imzadan alınan h
    element_init_G1(result.h, params.pairing);
    element_set(result.h, blindSig.h);
    
    // (1) Hash(comi) kontrolü:
    element_t h_check;
    element_init_G1(h_check, params.pairing);
    hashToG1(h_check, params, bsOut.comi);
    result.debug.hash_comi = elementToStringG1(h_check);
    std::cout << "[UNBLIND DEBUG] Hash(comi) = " << result.debug.hash_comi << "\n";
    std::cout << "[UNBLIND DEBUG] h         = " << elementToStringG1(bsOut.h) << "\n";
    if(element_cmp(h_check, bsOut.h) != 0) {
        element_clear(h_check);
        throw std::runtime_error("unblindSign: Hash(comi) != h");
    }
    element_clear(h_check);
    
    // (2) sₘ = cm · (β₂)^(–o)
    mpz_t neg_o;
    mpz_init(neg_o);
    mpz_neg(neg_o, bsOut.o);
    mpz_mod(neg_o, neg_o, params.prime_order);
    
    // Üstel için Zr tipi element oluşturuyoruz:
    element_t exponent;
    element_init_Zr(exponent, params.pairing);
    element_set_mpz(exponent, neg_o);
    mpz_clear(neg_o);
    
    element_t beta_pow;
    element_init_G1(beta_pow, params.pairing);
    element_pow_zn(beta_pow, eaKey.vkm2, exponent);
    element_clear(exponent);
    
    element_init_G1(result.s_m, params.pairing);
    element_mul(result.s_m, blindSig.cm, beta_pow);
    result.debug.computed_s_m = elementToStringG1(result.s_m);
    std::cout << "[UNBLIND DEBUG] Computed s_m = " << result.debug.computed_s_m << "\n";
    element_clear(beta_pow);
    
    // (3) Pairing kontrolü:
    // DID'i mpz_t'ye çevir:
    mpz_t didInt;
    mpz_init(didInt);
    didStringToMpz(didStr, didInt, params.prime_order);
    
    // Üstel için yeniden Zr tipi element oluştur:
    element_init_Zr(exponent, params.pairing);
    element_set_mpz(exponent, didInt);
    mpz_clear(didInt);
    
    element_t beta_did;
    element_init_G1(beta_did, params.pairing);
    element_pow_zn(beta_did, eaKey.vkm2, exponent);
    element_clear(exponent);
    
    // multiplier = α₂ * beta_did (EA key: α₂ = vkm1)
    element_t multiplier;
    element_init_G1(multiplier, params.pairing);
    element_mul(multiplier, eaKey.vkm1, beta_did);
    element_clear(beta_did);
    
    element_t pairing_lhs, pairing_rhs;
    element_init_GT(pairing_lhs, params.pairing);
    element_init_GT(pairing_rhs, params.pairing);
    pairing_apply(pairing_lhs, result.h, multiplier, params.pairing);
    element_clear(multiplier);
    pairing_apply(pairing_rhs, result.s_m, params.g2, params.pairing);
    
    // GT elemanlarını string'e çevirmek için:
    std::string lhs_str, rhs_str;
    {
        int len = element_length_in_bytes(pairing_lhs);
        std::vector<unsigned char> buf(len);
        element_to_bytes(buf.data(), pairing_lhs);
        std::ostringstream oss;
        oss << std::hex << std::setfill('0');
        for(auto c : buf)
            oss << std::setw(2) << (int)c;
        lhs_str = oss.str();
    }
    {
        int len = element_length_in_bytes(pairing_rhs);
        std::vector<unsigned char> buf(len);
        element_to_bytes(buf.data(), pairing_rhs);
        std::ostringstream oss;
        oss << std::hex << std::setfill('0');
        for(auto c : buf)
            oss << std::setw(2) << (int)c;
        rhs_str = oss.str();
    }
    result.debug.pairing_lhs = lhs_str;
    result.debug.pairing_rhs = rhs_str;
    std::cout << "[UNBLIND DEBUG] pairing_lhs = " << lhs_str << "\n";
    std::cout << "[UNBLIND DEBUG] pairing_rhs = " << rhs_str << "\n";
    
    bool pairing_ok = (element_cmp(pairing_lhs, pairing_rhs) == 0);
    element_clear(pairing_lhs);
    element_clear(pairing_rhs);
    if(!pairing_ok) {
        throw std::runtime_error("unblindSign: Pairing check failed");
    }
    std::cout << "[UNBLIND DEBUG] Pairing check PASSED\n";
    
    return result;
}
