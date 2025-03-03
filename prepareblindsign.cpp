#include "prepareblindsign.h"
#include <openssl/sha.h>
#include <stdexcept>
#include <vector>
#include <sstream>
#include <iomanip>
#include <random>

/*
  randomZr: element Zr random
*/
static void randomZr(element_t zr, TIACParams &params) {
    element_random(zr); 
}

/*
  didStringToMpz: interpret DID string as big hex or decimal
                  mod p. We'll do hex parse if needed.
*/
static void didStringToMpz(const std::string &didStr, mpz_t rop, const mpz_t p) {
    // interpret the hex DID
    if (mpz_set_str(rop, didStr.c_str(), 16) != 0) {
        // if that fails, try decimal:
        if (mpz_set_str(rop, didStr.c_str(), 10) != 0) {
            throw std::runtime_error("didStringToMpz: invalid DID string");
        }
    }
    mpz_mod(rop, rop, p);
}

/*
  elementToStringG1: canonical bytes => hex
*/
static std::string elementToStringG1(element_t e) {
    int len = element_length_in_bytes(e);
    std::vector<unsigned char> buf(len);
    element_to_bytes(buf.data(), e);

    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (auto c : buf) {
        oss << std::setw(2) << (int)c;
    }
    return oss.str();
}

/*
  hashToG1: convert a string => G1 using element_from_hash
*/
static void hashToG1(element_t outG1, TIACParams &params, element_t inElem) {
    // convert inElem => hex string
    std::string s = elementToStringG1(inElem);
    // map to G1
    element_from_hash(outG1, s.data(), s.size());
}

/*
  computeKoR: (Alg.6) [We won't do full check here, we just build a stub]
*/
static KoRProof computeKoR(
    TIACParams &params,
    element_t com,
    element_t comi,
    element_t g1,
    element_t h1,
    element_t h,
    mpz_t oi,
    mpz_t did,
    mpz_t o
) {
    // We'll skip the full details (like you did).
    KoRProof proof;
    element_init_Zr(proof.c,  params.pairing);
    element_init_Zr(proof.s1, params.pairing);
    element_init_Zr(proof.s2, params.pairing);
    element_init_Zr(proof.s3, params.pairing);
    element_set0(proof.c);
    element_set0(proof.s1);
    element_set0(proof.s2);
    element_set0(proof.s3);
    return proof;
}

PrepareBlindSignOutput prepareBlindSign(TIACParams &params, const std::string &didStr) {
    PrepareBlindSignOutput out;
    mpz_t oi, o;
    mpz_inits(oi, o, NULL);

    // 1) random
    element_t tmp;
    element_init_Zr(tmp, params.pairing);
    element_random(tmp);
    element_to_mpz(oi, tmp); 
    element_random(tmp);
    element_to_mpz(o, tmp); 
    element_clear(tmp);

    // 2) parse DID => mpz
    mpz_t didInt;
    mpz_init(didInt);
    didStringToMpz(didStr, didInt, params.prime_order);

    // comi = g1^oi * h1^did
    element_init_G1(out.comi, params.pairing);
    {
        element_t g1_oi, h1_did;
        element_init_G1(g1_oi,   params.pairing);
        element_init_G1(h1_did, params.pairing);

        element_t exp;
        element_init_Zr(exp, params.pairing);

        // g1^oi
        element_set_mpz(exp, oi);
        element_pow_zn(g1_oi, params.g1, exp);

        // h1^did
        element_set_mpz(exp, didInt);
        element_pow_zn(h1_did, params.h1, exp);

        element_mul(out.comi, g1_oi, h1_did);

        element_clear(g1_oi);
        element_clear(h1_did);
        element_clear(exp);
    }

    // h = HashInG1(comi)
    element_init_G1(out.h, params.pairing);
    hashToG1(out.h, params, out.comi);

    // com = g1^o * h^did
    element_init_G1(out.com, params.pairing);
    {
        element_t g1_o, h_did;
        element_init_G1(g1_o, params.pairing);
        element_init_G1(h_did, params.pairing);
        element_t exp;
        element_init_Zr(exp, params.pairing);

        // g1^o
        element_set_mpz(exp, o);
        element_pow_zn(g1_o, params.g1, exp);
        // h^did
        element_set_mpz(exp, didInt);
        element_pow_zn(h_did, out.h, exp);

        element_mul(out.com, g1_o, h_did);

        element_clear(g1_o);
        element_clear(h_did);
        element_clear(exp);
    }

    // pi_s
    out.pi_s = computeKoR(params, out.com, out.comi, params.g1, params.h1, out.h, oi, didInt, o);

    // store o
    mpz_init(out.o);
    mpz_set(out.o, o);

    mpz_clears(oi, o, didInt, NULL);
    return out;
}
