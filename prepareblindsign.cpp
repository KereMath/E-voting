#include "prepareblindsign.h"
#include <openssl/sha.h>
#include <vector>
#include <random>
#include <sstream>
#include <iomanip>

// Rastgele element Zr
static void randomZr(element_t zr, const TIACParams &params) {
    element_random(zr); 
}

// DID string (hex) -> mpz (mod p)
static void didStringToMpz(const std::string &didStr, mpz_t rop, const mpz_t p) {
    mpz_set_str(rop, didStr.c_str(), 16);
    mpz_mod(rop, rop, p);
}

// G1 elemanini string'e çevir (burada const_cast gerekli)
static std::string elementToStringG1(const element_t g1Elem) {
    // G1 elemanı uzunluk
    int length = element_length_in_bytes(const_cast<element_t>(g1Elem)); // <--- const_cast
    std::vector<unsigned char> buf(length);

    // Elemanı byte dizisine
    element_to_bytes(buf.data(), const_cast<element_t>(g1Elem)); // <--- const_cast

    // Byte'ları hex string'e dönüştür
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for(unsigned char c : buf) {
        oss << std::setw(2) << (int)c;
    }
    return oss.str();
}

// G1'e hash (comi'den G1'e)
static void hashToG1(element_t g1Elem, const TIACParams &params, const element_t input) {
    std::string s = elementToStringG1(input);
    // PBC fonksiyonu: element_from_hash(e, data, len)
    //  -> e (G1) = HashToCurve(data)
    element_from_hash(g1Elem, s.data(), s.size());
}

// c = Hash(...) -> Zr
//  param elemsG1: bir dizi G1 elemanı
static void hashToZr(element_t zr, const TIACParams &params, const std::vector<element_t> &elemsG1)
{
    // Her G1 elemanini string'e cevirip birlestiriyoruz
    std::ostringstream oss;
    for(const auto &e : elemsG1) {
        oss << elementToStringG1(e); // her G1'i hex string yapip ekle
    }

    // SHA512
    unsigned char hash[SHA512_DIGEST_LENGTH];
    std::string msg = oss.str();
    SHA512((const unsigned char*)msg.data(), msg.size(), hash);

    // mpz'ye aktar
    mpz_t temp;
    mpz_init(temp);
    mpz_import(temp, SHA512_DIGEST_LENGTH, 1, 1, 0, 0, hash);
    mpz_mod(temp, temp, params.prime_order);

    element_set_mpz(zr, temp);
    mpz_clear(temp);
}

// Algoritma 5: KoRProof
static KoRProof computeKoR(const TIACParams &params, 
                           const element_t com, 
                           const element_t comi,
                           const element_t g1, 
                           const element_t h1, 
                           const element_t h,
                           const mpz_t oi,
                           const mpz_t did,
                           const mpz_t o)
{
    // 1) r1, r2, r3 ∈ Zr
    element_t r1, r2, r3;
    element_init_Zr(r1, const_cast<pairing_t>(params.pairing));  // <--- const_cast
    element_init_Zr(r2, const_cast<pairing_t>(params.pairing));  // <--- const_cast
    element_init_Zr(r3, const_cast<pairing_t>(params.pairing));  // <--- const_cast

    randomZr(r1, params);
    randomZr(r2, params);
    randomZr(r3, params);

    // 2) com'i = g1^r1 * h1^r2
    element_t comi_prime;
    element_init_G1(comi_prime, const_cast<pairing_t>(params.pairing)); // <--- const_cast

    element_t g1_r1; 
    element_init_G1(g1_r1, const_cast<pairing_t>(params.pairing)); // <--- const_cast
    element_pow_zn(g1_r1, const_cast<element_t>(g1), r1);           // <--- const_cast

    element_t h1_r2;
    element_init_G1(h1_r2, const_cast<pairing_t>(params.pairing)); // <--- const_cast
    element_pow_zn(h1_r2, const_cast<element_t>(h1), r2);          // <--- const_cast

    element_mul(comi_prime, g1_r1, h1_r2);

    element_clear(g1_r1);
    element_clear(h1_r2);

    // 3) com' = g1^r3 * h^r2
    element_t com_prime;
    element_init_G1(com_prime, const_cast<pairing_t>(params.pairing)); // <--- const_cast

    element_t g1_r3;
    element_init_G1(g1_r3, const_cast<pairing_t>(params.pairing)); // <--- const_cast
    element_pow_zn(g1_r3, const_cast<element_t>(g1), r3);          // <--- const_cast

    element_t h_r2;
    element_init_G1(h_r2, const_cast<pairing_t>(params.pairing));  // <--- const_cast
    element_pow_zn(h_r2, const_cast<element_t>(h), r2);            // <--- const_cast

    element_mul(com_prime, g1_r3, h_r2);

    element_clear(g1_r3);
    element_clear(h_r2);

    // 4) c = Hash( [g1, h, h1, com, comi, com_prime, comi_prime] )
    KoRProof proof;
    element_init_Zr(proof.c,  const_cast<pairing_t>(params.pairing)); // <--- const_cast
    element_init_Zr(proof.s1, const_cast<pairing_t>(params.pairing)); // <--- const_cast
    element_init_Zr(proof.s2, const_cast<pairing_t>(params.pairing)); // <--- const_cast
    element_init_Zr(proof.s3, const_cast<pairing_t>(params.pairing)); // <--- const_cast

    // Vector'a ekliyoruz
    std::vector<element_t> toHash = {
        const_cast<element_t>(g1),
        const_cast<element_t>(h),
        const_cast<element_t>(h1),
        const_cast<element_t>(com),
        const_cast<element_t>(comi),
        com_prime,
        comi_prime
    };
    hashToZr(proof.c, params, toHash);

    // c -> mpz
    mpz_t c_mpz;
    mpz_init(c_mpz);
    element_to_mpz(c_mpz, proof.c);

    // r1,r2,r3 -> mpz
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

PrepareBlindSignOutput prepareBlindSign(const TIACParams &params, const std::string &didStr) {
    PrepareBlindSignOutput out;

    // 1) oi ∈ Zp, 4) o ∈ Zp
    mpz_t oi, o;
    mpz_inits(oi, o, NULL);

    // Rastgele
    {
        element_t tmp;
        element_init_Zr(tmp, const_cast<pairing_t>(params.pairing)); // <--- const_cast
        element_random(tmp);
        element_to_mpz(oi, tmp);
        element_clear(tmp);
    }
    {
        element_t tmp;
        element_init_Zr(tmp, const_cast<pairing_t>(params.pairing)); // <--- const_cast
        element_random(tmp);
        element_to_mpz(o, tmp);
        element_clear(tmp);
    }

    // DID'i mpz'e çevir
    mpz_t didInt;
    mpz_init(didInt);
    didStringToMpz(didStr, didInt, params.prime_order);

    // 2) comi = g1^oi * h1^DID
    element_init_G1(out.comi, const_cast<pairing_t>(params.pairing)); // <--- const_cast
    {
        // g1^oi
        element_t g1_oi;
        element_init_G1(g1_oi, const_cast<pairing_t>(params.pairing)); // <--- const_cast

        {
            element_t exp;
            element_init_Zr(exp, const_cast<pairing_t>(params.pairing)); // <--- const_cast
            element_set_mpz(exp, oi);
            element_pow_zn(g1_oi, const_cast<element_t>(params.g1), exp); // <--- const_cast
            element_clear(exp);
        }

        // h1^did
        element_t h1_did;
        element_init_G1(h1_did, const_cast<pairing_t>(params.pairing)); // <--- const_cast
        {
            element_t exp;
            element_init_Zr(exp, const_cast<pairing_t>(params.pairing)); // <--- const_cast
            element_set_mpz(exp, didInt);
            element_pow_zn(h1_did, const_cast<element_t>(params.h1), exp); // <--- const_cast
            element_clear(exp);
        }

        element_mul(out.comi, g1_oi, h1_did);

        element_clear(g1_oi);
        element_clear(h1_did);
    }

    // 3) h = HashInG1(comi)
    element_init_G1(out.h, const_cast<pairing_t>(params.pairing)); // <--- const_cast
    hashToG1(out.h, params, out.comi);

    // 5) com = g1^o * h^DID
    element_init_G1(out.com, const_cast<pairing_t>(params.pairing)); // <--- const_cast
    {
        // g1^o
        element_t g1_o;
        element_init_G1(g1_o, const_cast<pairing_t>(params.pairing)); // <--- const_cast
        {
            element_t exp;
            element_init_Zr(exp, const_cast<pairing_t>(params.pairing)); // <--- const_cast
            element_set_mpz(exp, o);
            element_pow_zn(g1_o, const_cast<element_t>(params.g1), exp);  // <--- const_cast
            element_clear(exp);
        }

        // h^DID
        element_t h_did;
        element_init_G1(h_did, const_cast<pairing_t>(params.pairing)); // <--- const_cast
        {
            element_t exp;
            element_init_Zr(exp, const_cast<pairing_t>(params.pairing)); // <--- const_cast
            element_set_mpz(exp, didInt);
            element_pow_zn(h_did, out.h, exp);
            element_clear(exp);
        }

        element_mul(out.com, g1_o, h_did);
        element_clear(g1_o);
        element_clear(h_did);
    }

    // 6) pi_s = computeKoR(...)
    out.pi_s = computeKoR(params, out.com, out.comi, 
                          params.g1, params.h1, out.h,
                          oi, didInt, o);

    // temizlik
    mpz_clears(oi, o, didInt, NULL);
    return out;
}
