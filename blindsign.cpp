#include "blindsign.h"
#include <openssl/sha.h>
#include <vector>
#include <sstream>
#include <iomanip>
#include <stdexcept>
#include <iostream>
#include <numeric>
#include <algorithm>

std::string elemToStrG1(element_t elem) {
    int len = element_length_in_bytes(elem);
    std::vector<unsigned char> buf(len);
    element_to_bytes(buf.data(), elem);
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (unsigned char c : buf) {
        oss << std::setw(2) << (int)c;
    }
    return oss.str();
}

static void hashToZr(element_t outZr, TIACParams &params, const std::vector<element_s*> &g1Elems) {
    std::ostringstream oss;
    for (auto ePtr : g1Elems) {
        oss << elemToStrG1(ePtr);
    }
    std::string data = oss.str();
    unsigned char digest[SHA512_DIGEST_LENGTH];
    SHA512(reinterpret_cast<const unsigned char*>(data.data()), data.size(), digest);
    mpz_t tmp;
    mpz_init(tmp);
    mpz_import(tmp, SHA512_DIGEST_LENGTH, 1, 1, 0, 0, digest);
    mpz_mod(tmp, tmp, params.prime_order);
    element_set_mpz(outZr, tmp);
    mpz_clear(tmp);
}

bool CheckKoR(TIACParams &params, element_t com, element_t comi, element_t h, KoRProof &pi_s) {
    element_t comi_double;
    element_init_G1(comi_double, params.pairing);
    element_t g1_s1; 
    element_init_G1(g1_s1, params.pairing);
    element_pow_zn(g1_s1, params.g1, pi_s.s1);
    element_t h1_s2; 
    element_init_G1(h1_s2, params.pairing);
    element_pow_zn(h1_s2, params.h1, pi_s.s2);
    element_t comi_c; 
    element_init_G1(comi_c, params.pairing);
    element_pow_zn(comi_c, comi, pi_s.c);
    element_mul(comi_double, g1_s1, h1_s2);
    element_clear(g1_s1);
    element_clear(h1_s2);
    element_mul(comi_double, comi_double, comi_c);
    element_clear(comi_c);
    element_t com_double;
    element_init_G1(com_double, params.pairing);
    element_t g1_s3;
    element_init_G1(g1_s3, params.pairing);
    element_pow_zn(g1_s3, params.g1, pi_s.s3);
    element_t h_s2;
    element_init_G1(h_s2, params.pairing);
    element_pow_zn(h_s2, h, pi_s.s2);
    element_t com_c;
    element_init_G1(com_c, params.pairing);
    element_pow_zn(com_c, com, pi_s.c);
    element_mul(com_double, g1_s3, h_s2);
    element_mul(com_double, com_double, com_c);
    element_clear(g1_s3);
    element_clear(h_s2);
    element_clear(com_c);
    element_t cprime;
    element_init_Zr(cprime, params.pairing);
    std::vector<element_s*> toHash;
    toHash.reserve(7);
    toHash.push_back(params.g1);
    toHash.push_back(h);
    toHash.push_back(params.h1);
    toHash.push_back(com);
    toHash.push_back(com_double);
    toHash.push_back(comi);
    toHash.push_back(comi_double);
    hashToZr(cprime, params, toHash);
    bool ok = (element_cmp(cprime, pi_s.c) == 0);
    element_clear(comi_double);
    element_clear(com_double);
    element_clear(cprime);
    return ok;
}

BlindSignature blindSign(TIACParams &params, PrepareBlindSignOutput &bsOut, mpz_t xm, mpz_t ym, int adminId, int voterId) {
    bool ok = CheckKoR(params, bsOut.com, bsOut.comi, bsOut.h, bsOut.pi_s);
    if(!ok) {
        throw std::runtime_error("blindSign: KoR check failed");
    }
    element_t hprime;
    element_init_G1(hprime, params.pairing);
    {
        std::string s = elemToStrG1(bsOut.comi);
        element_from_hash(hprime, s.data(), s.size());
    }
    if(element_cmp(hprime, bsOut.h) != 0) {
        element_clear(hprime);
        throw std::runtime_error("blindSign: Hash(comi) != h => hata");
    }
    element_clear(hprime);
    BlindSignature sig;
    element_init_G1(sig.h, params.pairing);
    element_init_G1(sig.cm, params.pairing);
    element_set(sig.h, bsOut.h);
    element_t hx;
    element_init_G1(hx, params.pairing);
    {
        element_t expX;
        element_init_Zr(expX, params.pairing);
        element_set_mpz(expX, xm);
        element_pow_zn(hx, bsOut.h, expX);
        element_clear(expX);
    }
    element_t comy;
    element_init_G1(comy, params.pairing);
    {
        element_t expY;
        element_init_Zr(expY, params.pairing);
        element_set_mpz(expY, ym);
        element_pow_zn(comy, bsOut.com, expY);
        element_clear(expY);
    }
    element_mul(sig.cm, hx, comy);
    element_clear(hx);
    element_clear(comy);
    sig.adminId = adminId;
    sig.voterId = voterId;
    return sig;
}