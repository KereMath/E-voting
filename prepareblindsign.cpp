#include "prepareblindsign.h"
#include <openssl/sha.h>
#include <vector>
#include <random>
#include <sstream>
#include <iomanip>

// Yardımcı fonksiyon: rastgele element Zr mod p
static void randomZr(element_t zr, const TIACParams &params) {
    // element_random(zr) -> [0, r-1] ama deterministik degil, 
    // pbc kendi entropisine gore. 
    // Eger kendimiz mpz tabanli bir RNG istersek asagidaki 
    // gibi yapabilirdik, simdilik element_random kullanmak kolay.
    element_random(zr);
}

// DID string (hex) -> mpz (mod p). 
//  Hash olarak 512 bit bir hex string gelebilir; p 256-512 bit civari. 
//  Bu ornekte DID'i mod p'ye indirgiyoruz.
static void didStringToMpz(const std::string &didStr, mpz_t rop, const mpz_t p) {
    // Örneğin hex string'i mpz'ye import edelim:
    mpz_set_str(rop, didStr.c_str(), 16);
    // mod p
    mpz_mod(rop, rop, p);
}

// G1 elemanini string'e cevir
static std::string elementToStringG1(const element_t g1Elem) {
    // element için binary format
    int length = element_length_in_bytes(g1Elem);
    std::vector<unsigned char> buf(length);
    element_to_bytes(buf.data(), g1Elem);

    // Hex string'e cevirelim
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for(unsigned char c : buf) {
        oss << std::setw(2) << (int)c;
    }
    return oss.str();
}

// element_from_hash() icin, veriye cevirme
// PBC: element_from_hash(e, data, len) => e nin turu G1 se 
// (Type 3 pairingde) curve uzerinde hashing yapiyor.
static void hashToG1(element_t g1Elem, const TIACParams &params, const element_t input) {
    // input G1. Onu string'e cevir, sonra e.g. element_from_hash
    std::string s = elementToStringG1(input);
    element_from_hash(g1Elem, (void*)s.data(), s.size());
}

// Basit bir "Hash(...)" -> element Zr (Algoritma 5, adım 4)
//  c = Hash(g1, h, h1, com, com', comi, com'i) mod p
//  Bu ornekte her seyi string'e donusturup, SHA-512 -> mod p yapiyoruz
static void hashToZr(element_t zr, const TIACParams &params, 
                     const std::vector<element_t> &elemsG1) 
{
    // Hepsi G1 oldugu icin, sirayla string'e donusturelim
    std::ostringstream oss;
    for(const auto &e : elemsG1) {
        oss << elementToStringG1(e);
    }

    // oss.str() -> sha-512
    unsigned char hash[SHA512_DIGEST_LENGTH];
    std::string msg = oss.str();
    SHA512((const unsigned char*)msg.data(), msg.size(), hash);

    // mpz ye import
    mpz_t temp;
    mpz_init(temp);
    mpz_import(temp, SHA512_DIGEST_LENGTH, 1, 1, 0, 0, hash);
    mpz_mod(temp, temp, params.prime_order);

    element_set_mpz(zr, temp);
    mpz_clear(temp);
}

// KoRProof fonksiyonu (Algoritma 5)
//  KoR(com, comi) = (c, s1, s2, s3)
static KoRProof computeKoR(const TIACParams &params, 
                           const element_t com, 
                           const element_t comi,
                           const element_t g1, 
                           const element_t h1, 
                           const element_t h,
                           const mpz_t oi,   // random exponent for comi
                           const mpz_t did,  // DID integer mod p
                           const mpz_t o)    // random exponent for com
{
    // 1) r1, r2, r3 in Zp random
    element_t r1, r2, r3;
    element_init_Zr(r1, params.pairing);
    element_init_Zr(r2, params.pairing);
    element_init_Zr(r3, params.pairing);

    randomZr(r1, params);
    randomZr(r2, params);
    randomZr(r3, params);

    // 2) com'i = g1^r1 * h1^r2
    element_t comi_prime;
    element_init_G1(comi_prime, params.pairing);

    // g1^r1
    element_t g1_r1; 
    element_init_G1(g1_r1, params.pairing);
    element_pow_zn(g1_r1, g1, r1);

    // h1^r2
    element_t h1_r2;
    element_init_G1(h1_r2, params.pairing);
    element_pow_zn(h1_r2, h1, r2);

    // comi_prime = g1^r1 * h1^r2
    element_mul(comi_prime, g1_r1, h1_r2);

    // Temizlik
    element_clear(g1_r1);
    element_clear(h1_r2);

    // 3) com' = g1^r3 * h^r2
    element_t com_prime;
    element_init_G1(com_prime, params.pairing);

    // g1^r3
    element_t g1_r3;
    element_init_G1(g1_r3, params.pairing);
    element_pow_zn(g1_r3, g1, r3);

    // h^r2
    element_t h_r2;
    element_init_G1(h_r2, params.pairing);
    element_pow_zn(h_r2, h, r2);

    // com_prime = g1^r3 * h^r2
    element_mul(com_prime, g1_r3, h_r2);

    // Temizlik
    element_clear(g1_r3);
    element_clear(h_r2);

    // 4) c = Hash(g1, h, h1, com, comi, com_prime, comi_prime)
    //    Hepsi G1 elemani -> string -> SHA512 -> mod p
    KoRProof proof;
    element_init_Zr(proof.c,  params.pairing);
    element_init_Zr(proof.s1, params.pairing);
    element_init_Zr(proof.s2, params.pairing);
    element_init_Zr(proof.s3, params.pairing);

    std::vector<element_t> toHash = {
        g1, h, h1, com, comi, com_prime, comi_prime
    };
    hashToZr(proof.c, params, toHash);

    // c'yi mpz'e cevir
    mpz_t c_mpz;
    mpz_init(c_mpz);
    element_to_mpz(c_mpz, proof.c);

    // 5) s1 = r1 - c * oi
    // 6) s2 = r2 - c * DID
    // 7) s3 = r3 - c * o
    mpz_t r1_mpz, r2_mpz, r3_mpz;
    mpz_inits(r1_mpz, r2_mpz, r3_mpz, NULL);

    element_to_mpz(r1_mpz, r1);
    element_to_mpz(r2_mpz, r2);
    element_to_mpz(r3_mpz, r3);

    // s1
    mpz_t s1_mpz;
    mpz_init(s1_mpz);
    mpz_mul(s1_mpz, c_mpz, oi);
    mpz_sub(s1_mpz, r1_mpz, s1_mpz);
    mpz_mod(s1_mpz, s1_mpz, params.prime_order);
    element_set_mpz(proof.s1, s1_mpz);

    // s2
    mpz_t s2_mpz;
    mpz_init(s2_mpz);
    mpz_mul(s2_mpz, c_mpz, did);
    mpz_sub(s2_mpz, r2_mpz, s2_mpz);
    mpz_mod(s2_mpz, s2_mpz, params.prime_order);
    element_set_mpz(proof.s2, s2_mpz);

    // s3
    mpz_t s3_mpz;
    mpz_init(s3_mpz);
    mpz_mul(s3_mpz, c_mpz, o);
    mpz_sub(s3_mpz, r3_mpz, s3_mpz);
    mpz_mod(s3_mpz, s3_mpz, params.prime_order);
    element_set_mpz(proof.s3, s3_mpz);

    // Temizlik
    mpz_clears(c_mpz, r1_mpz, r2_mpz, r3_mpz, s1_mpz, s2_mpz, s3_mpz, NULL);
    element_clear(r1);
    element_clear(r2);
    element_clear(r3);
    element_clear(comi_prime);
    element_clear(com_prime);

    return proof;
}

// Algoritma 4: prepareBlindSign()
PrepareBlindSignOutput prepareBlindSign(const TIACParams &params, const std::string &didStr) {
    PrepareBlindSignOutput out;

    // 1) oi ∈ Zp rastgele
    mpz_t oi;
    mpz_init(oi);

    // 4) o ∈ Zp rastgele
    mpz_t o;
    mpz_init(o);

    // Rastgele element Zr
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

    // DID'i mpz'e çevir
    mpz_t didInt;
    mpz_init(didInt);
    didStringToMpz(didStr, didInt, params.prime_order);

    // out.comi = g1^oi * h1^DID
    element_init_G1(out.comi, params.pairing);
    {
        // g1^oi
        element_t g1_oi;
        element_init_G1(g1_oi, params.pairing);
        {
            element_t exp;
            element_init_Zr(exp, params.pairing);
            element_set_mpz(exp, oi);
            element_pow_zn(g1_oi, params.g1, exp);
            element_clear(exp);
        }

        // h1^did
        element_t h1_did;
        element_init_G1(h1_did, params.pairing);
        {
            element_t exp;
            element_init_Zr(exp, params.pairing);
            element_set_mpz(exp, didInt);
            element_pow_zn(h1_did, params.h1, exp);
            element_clear(exp);
        }

        // comi = g1_oi * h1_did
        element_mul(out.comi, g1_oi, h1_did);

        element_clear(g1_oi);
        element_clear(h1_did);
    }

    // 3) h = HashInG1(comi)
    element_init_G1(out.h, params.pairing);
    hashToG1(out.h, params, out.comi);

    // 5) com = g1^o * h^DID
    element_init_G1(out.com, params.pairing);
    {
        // g1^o
        element_t g1_o;
        element_init_G1(g1_o, params.pairing);
        {
            element_t exp;
            element_init_Zr(exp, params.pairing);
            element_set_mpz(exp, o);
            element_pow_zn(g1_o, params.g1, exp);
            element_clear(exp);
        }

        // h^did
        element_t h_did;
        element_init_G1(h_did, params.pairing);
        {
            element_t exp;
            element_init_Zr(exp, params.pairing);
            element_set_mpz(exp, didInt);
            element_pow_zn(h_did, out.h, exp);
            element_clear(exp);
        }

        // com = g1_o * h_did
        element_mul(out.com, g1_o, h_did);

        element_clear(g1_o);
        element_clear(h_did);
    }

    // 6) πs = KoR(com, comi) -> (c, s1, s2, s3)
    out.pi_s = computeKoR(params, out.com, out.comi, 
                          params.g1, params.h1, out.h,
                          oi, didInt, o);

    // Temizlik
    mpz_clear(oi);
    mpz_clear(o);
    mpz_clear(didInt);

    return out;
}
