#include "unblindsign.h"
#include <openssl/sha.h>
#include <vector>
#include <sstream>
#include <iomanip>
#include <stdexcept>
#include <iostream>

static std::string mpzToString(const mpz_t value) {
    char* c_str = mpz_get_str(nullptr, 10, value);
    std::string str(c_str);
    free(c_str);
    return str;
}

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

static void didStringToMpz(const std::string &didStr, mpz_t rop, const mpz_t p) {
    if(mpz_set_str(rop, didStr.c_str(), 16) != 0)
        throw std::runtime_error("didStringToMpz: invalid hex string");
    mpz_mod(rop, rop, p);
}

static void hashToG1(element_t outG1, TIACParams &params, element_t inElem) {
    std::string s = elementToStringG1(inElem);
    element_from_hash(outG1, s.data(), s.size());
    std::string outStr = elementToStringG1(outG1);
}

static void hashToZr(element_t outZr, TIACParams &params, const std::vector<std::string> &elems) {
    std::ostringstream oss;
    for (const auto &s : elems)
        oss << s;
    std::string msg = oss.str();
    unsigned char digest[SHA512_DIGEST_LENGTH];
    SHA512(reinterpret_cast<const unsigned char*>(msg.data()), msg.size(), digest);
    for (int i = 0; i < SHA512_DIGEST_LENGTH; i++) {
    }
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
    mpz_clear(tmp);
}

UnblindSignature unblindSign(TIACParams &params,PrepareBlindSignOutput &bsOut,BlindSignature &blindSig,EAKey &eaKey,const std::string &didStr) {
    UnblindSignature result;
    element_init_G1(result.h, params.pairing);
    element_set(result.h, blindSig.h);    
    element_t h_check;
    element_init_G1(h_check, params.pairing);
    hashToG1(h_check, params, bsOut.comi);
    result.debug.hash_comi = elementToStringG1(h_check);
    if(element_cmp(h_check, bsOut.h) != 0) {
        element_clear(h_check);
        throw std::runtime_error("unblindSign: Hash(comi) != h");
    }
    element_clear(h_check);
    mpz_t neg_o;
    mpz_init(neg_o);
    mpz_neg(neg_o, bsOut.o);
    mpz_mod(neg_o, neg_o, params.prime_order);
    element_t exponent;
    element_init_Zr(exponent, params.pairing);
    element_set_mpz(exponent, neg_o);
    mpz_clear(neg_o);
    element_t beta_pow;
    element_init_G1(beta_pow, params.pairing);
    element_pow_zn(beta_pow, eaKey.vkm3, exponent);
    element_clear(exponent);
    element_init_G1(result.s_m, params.pairing);
    element_mul(result.s_m, blindSig.cm, beta_pow);
    result.debug.computed_s_m = elementToStringG1(result.s_m);
    element_clear(beta_pow);
    mpz_t didInt;
    mpz_init(didInt);
    didStringToMpz(didStr, didInt, params.prime_order);
    element_init_Zr(exponent, params.pairing);
    element_set_mpz(exponent, didInt);
    mpz_clear(didInt);
    element_t beta_did;
    element_init_G1(beta_did, params.pairing);
    element_pow_zn(beta_did, eaKey.vkm2, exponent);
    element_clear(exponent);
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
    bool pairing_ok = (element_cmp(pairing_lhs, pairing_rhs) == 0);
    element_clear(pairing_lhs);
    element_clear(pairing_rhs);
    if(!pairing_ok) {
        throw std::runtime_error("unblindSign: Pairing check failed");
    }    
    return result;
}
