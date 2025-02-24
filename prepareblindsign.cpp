#include "prepareblindsign.h"
#include <openssl/sha.h>
#include <vector>
#include <random>
#include <sstream>
#include <iomanip>
#include <stdexcept>

/*
  * Kodun amacı:
  *  - Algoritma 4: comi, h, com, pi_s
  *  - Algoritma 5: KoRProof
  *
  * Dikkat: PBC'de "element_t" = "struct element_s[1]" 
  * => &g1 tipik "element_s(*)[1]" olur. 
  * => Bu yüzden "std::vector<element_t*> toHash = {&g1, ...}" dersek hata. 
  *    Onun yerine "toHash.push_back(&g1[0])" yapılır.
*/

// Rastgele element Zr
static void randomZr(element_t zr, TIACParams &params) {
    element_random(zr);
}

// DID (hex) -> mpz (mod p)
static void didStringToMpz(const std::string &didStr, mpz_t rop, const mpz_t p) {
    if (mpz_set_str(rop, didStr.c_str(), 16) != 0) {
        throw std::runtime_error("didStringToMpz: invalid hex string");
    }
    mpz_mod(rop, rop, p);
}

// G1 elemanını hex string’e çevir
static std::string elementToStringG1(element_t g1Elem) {
    // g1Elem => "struct element_s[1]" => pbc fonksiyonları
    int length = element_length_in_bytes(g1Elem);
    std::vector<unsigned char> buf(length);
    element_to_bytes(buf.data(), g1Elem);

    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for(unsigned char c : buf) {
        oss << std::setw(2) << (int)c;
    }
    return oss.str();
}

// outG1 = HashInG1(inElem)
static void hashToG1(element_t outG1, TIACParams &params, element_t inElem) {
    std::string s = elementToStringG1(inElem);
    element_from_hash(outG1, s.data(), s.size());
}

// c = Hash( [elems] ) -> Zr
// Burada "elems" = vector of (element_t*)
static void hashToZr(element_t outZr, TIACParams &params, const std::vector<element_t*> &elems) {
    std::ostringstream oss;
    for (auto ePtr : elems) {
        oss << elementToStringG1(*ePtr); 
    }
    std::string fullStr = oss.str();

    unsigned char hash[SHA512_DIGEST_LENGTH];
    SHA512((const unsigned char*)fullStr.data(), fullStr.size(), hash);

    mpz_t tmp;
    mpz_init(tmp);
    mpz_import(tmp, SHA512_DIGEST_LENGTH, 1, 1, 0, 0, hash);
    mpz_mod(tmp, tmp, params.prime_order);

    element_set_mpz(outZr, tmp);
    mpz_clear(tmp);
}

// Algoritma 5: KoR
static KoRProof computeKoR(
    TIACParams &params,
    element_t com,   // G1
    element_t comi,  // G1
    element_t g1,    // G1
    element_t h1,    // G1
    element_t h,     // G1
    mpz_t oi,        // Zp
    mpz_t did,       // Zp
    mpz_t o          // Zp
) {
    KoRProof proof;

    // r1, r2, r3 ∈ Zr
    element_t r1, r2, r3;
    element_init_Zr(r1, params.pairing);
    element_init_Zr(r2, params.pairing);
    element_init_Zr(r3, params.pairing);

    randomZr(r1, params);
    randomZr(r2, params);
    randomZr(r3, params);

    // comi' = g1^r1 * h1^r2
    element_t comi_prime;
    element_init_G1(comi_prime, params.pairing);

    element_t g1_r1;
    element_init_G1(g1_r1, params.pairing);
    element_pow_zn(g1_r1, g1, r1);

    element_t h1_r2;
    element_init_G1(h1_r2, params.pairing);
    element_pow_zn(h1_r2, h1, r2);

    element_mul(comi_prime, g1_r1, h1_r2);
    element_clear(g1_r1);
    element_clear(h1_r2);

    // com' = g1^r3 * h^r2
    element_t com_prime;
    element_init_G1(com_prime, params.pairing);

    element_t g1_r3;
    element_init_G1(g1_r3, params.pairing);
    element_pow_zn(g1_r3, g1, r3);

    element_t h_r2;
    element_init_G1(h_r2, params.pairing);
    element_pow_zn(h_r2, h, r2);

    element_mul(com_prime, g1_r3, h_r2);
    element_clear(g1_r3);
    element_clear(h_r2);

    // c = Hash([g1, h, h1, com, comi, com_prime, comi_prime])
    element_init_Zr(proof.c,  params.pairing);
    element_init_Zr(proof.s1, params.pairing);
    element_init_Zr(proof.s2, params.pairing);
    element_init_Zr(proof.s3, params.pairing);

    // Dikkat: "element_t" = "struct element_s[1]"
    // => &g1 => (element_s (*)[1])
    // => &g1[0] => (element_t*) 
    // vektöre push_back ile ekleyelim:
    std::vector<element_t*> toHash;
    toHash.reserve(7);
    toHash.push_back(&g1[0]);
    toHash.push_back(&h[0]);
    toHash.push_back(&h1[0]);
    toHash.push_back(&com[0]);
    toHash.push_back(&comi[0]);
    toHash.push_back(&com_prime[0]);
    toHash.push_back(&comi_prime[0]);

    hashToZr(proof.c, params, toHash);

    // c -> mpz
    mpz_t c_mpz;
    mpz_init(c_mpz);
    element_to_mpz(c_mpz, proof.c);

    // r1, r2, r3 -> mpz
    mpz_t r1_mpz, r2_mpz, r3_mpz;
    mpz_inits(r1_mpz, r2_mpz, r3_mpz, NULL);

    element_to_mpz(r1_mpz, r1);
    element_to_mpz(r2_mpz, r2);
    element_to_mpz(r3_mpz, r3);

    // s1 = r1 - c*oi
    mpz_t s1_mpz;
    mpz_init(s1_mpz);
    mpz_mul(s1_mpz, c_mpz, oi);
    mpz_sub(s1_mpz, r1_mpz, s1_mpz);
    mpz_mod(s1_mpz, s1_mpz, params.prime_order);
    element_set_mpz(proof.s1, s1_mpz);

    // s2 = r2 - c*did
    mpz_t s2_mpz;
    mpz_init(s2_mpz);
    mpz_mul(s2_mpz, c_mpz, did);
    mpz_sub(s2_mpz, r2_mpz, s2_mpz);
    mpz_mod(s2_mpz, s2_mpz, params.prime_order);
    element_set_mpz(proof.s2, s2_mpz);

    // s3 = r3 - c*o
    mpz_t s3_mpz;
    mpz_init(s3_mpz);
    mpz_mul(s3_mpz, c_mpz, o);
    mpz_sub(s3_mpz, r3_mpz, s3_mpz);
    mpz_mod(s3_mpz, s3_mpz, params.prime_order);
    element_set_mpz(proof.s3, s3_mpz);

    // temizlik
    mpz_clears(c_mpz, r1_mpz, r2_mpz, r3_mpz, s1_mpz, s2_mpz, s3_mpz, NULL);
    element_clear(r1);
    element_clear(r2);
    element_clear(r3);
    element_clear(com_prime);
    element_clear(comi_prime);

    return proof;
}

// Algoritma 4: prepareBlindSign
PrepareBlindSignOutput prepareBlindSign(TIACParams &params, const std::string &didStr) {
    PrepareBlindSignOutput out;

    // oi, o
    mpz_t oi, o;
    mpz_inits(oi, o, NULL);

    // Rastgele oi, o
    {
        element_t tmp;
        element_init_Zr(tmp, params.pairing);
        element_random(tmp);
        element_to_mpz(oi, tmp);
        element_clear(tmp);
    }
    {
        element_t tmp;
        element_init_Zr(tmp, params.pairing);
        element_random(tmp);
        element_to_mpz(o, tmp);
        element_clear(tmp);
    }

    // DID -> mpz
    mpz_t didInt;
    mpz_init(didInt);
    didStringToMpz(didStr, didInt, params.prime_order);

    // 2) comi = g1^oi * h1^did
    element_init_G1(out.comi, params.pairing);
    {
        element_t g1_oi;
        element_init_G1(g1_oi, params.pairing);

        {
            element_t exp;
            element_init_Zr(exp, params.pairing);
            element_set_mpz(exp, oi);
            element_pow_zn(g1_oi, params.g1, exp);
            element_clear(exp);
        }

        element_t h1_did;
        element_init_G1(h1_did, params.pairing);

        {
            element_t exp;
            element_init_Zr(exp, params.pairing);
            element_set_mpz(exp, didInt);
            element_pow_zn(h1_did, params.h1, exp);
            element_clear(exp);
        }

        element_mul(out.comi, g1_oi, h1_did);
        element_clear(g1_oi);
        element_clear(h1_did);
    }

    // 3) h = HashInG1(comi)
    element_init_G1(out.h, params.pairing);
    hashToG1(out.h, params, out.comi);

    // 5) com = g1^o * h^did
    element_init_G1(out.com, params.pairing);
    {
        element_t g1_o;
        element_init_G1(g1_o, params.pairing);

        {
            element_t exp;
            element_init_Zr(exp, params.pairing);
            element_set_mpz(exp, o);
            element_pow_zn(g1_o, params.g1, exp);
            element_clear(exp);
        }

        element_t h_did;
        element_init_G1(h_did, params.pairing);

        {
            element_t exp;
            element_init_Zr(exp, params.pairing);
            element_set_mpz(exp, didInt);
            element_pow_zn(h_did, out.h, exp);
            element_clear(exp);
        }

        element_mul(out.com, g1_o, h_did);
        element_clear(g1_o);
        element_clear(h_did);
    }

    // 6) pi_s = computeKoR(...)
    out.pi_s = computeKoR(params, 
                          out.com, 
                          out.comi, 
                          params.g1, 
                          params.h1, 
                          out.h,
                          oi,
                          didInt,
                          o);

    // temizlik
    mpz_clears(oi, o, didInt, NULL);

    return out;
}
