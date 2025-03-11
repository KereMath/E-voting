#include "checkkorverify.h"
#include <openssl/sha.h>
#include <sstream>
#include <iomanip>
#include <vector>
#include <stdexcept>
#include <iostream>

/**
 * Yardımcı fonksiyon: Bir element'i Zr, G1, G2 vb. farketmeden
 * non-const kopyalayabilmek için.
 */
static void copyConstElement(element_t dest, const element_t src, pairing_t pairing, int element_type) {
    // Elemanı ilgili type ile init edelim
    switch (element_type) {
        case 1: // G1
            element_init_G1(dest, pairing);
            break;
        case 2: // G2
            element_init_G2(dest, pairing);
            break;
        default: // Zr veya benzeri
            element_init_Zr(dest, pairing);
            break;
    }
    // Düşük seviyeli kopya
    element_t temp;
    temp[0] = *((element_s*)(&src[0]));
    // Dest'e set
    element_set(dest, temp);
}

/**
 * String (hex) -> bytes
 */
static std::vector<unsigned char> hexToBytes(const std::string &hex) {
    std::vector<unsigned char> bytes;
    bytes.reserve(hex.size() / 2);
    for (size_t i = 0; i + 1 < hex.size(); i += 2) {
        std::string byteStr = hex.substr(i, 2);
        unsigned char byte = (unsigned char)strtol(byteStr.c_str(), NULL, 16);
        bytes.push_back(byte);
    }
    return bytes;
}

/**
 * Helper: element'i hex string'e çevirir (G1/G2 farketmez).
 */
static std::string elementToHexStr(const element_t elem) {
    // non-const kopyası
    element_t tmp;
    tmp[0] = *((element_s*)(&elem[0]));
    
    int len = element_length_in_bytes(tmp);
    std::vector<unsigned char> buf(len);
    element_to_bytes(buf.data(), tmp);

    // Hex'e çevir
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (unsigned char c : buf) {
        oss << std::setw(2) << (int)c;
    }
    return oss.str();
}

/**
 * Helper: string -> element (G1)
 */
static void stringToElementG1(element_t result, const std::string &hexStr, pairing_t pairing) {
    element_init_G1(result, pairing);
    std::vector<unsigned char> bytes = hexToBytes(hexStr);
    if (bytes.empty()) {
        throw std::runtime_error("stringToElementG1: empty hex input");
    }
    if (element_from_bytes(result, bytes.data()) == 0) {
        throw std::runtime_error("stringToElementG1: element_from_bytes failed");
    }
}


/**
 * checkKoRVerify implementasyonu
 */
bool checkKoRVerify(
    TIACParams &params,
    const ProveCredentialOutput &proveRes,   // k, c, s1, s2, s3
    const MasterVerKey &mvk,                // alpha2, beta2, beta1
    const std::string &com_str,             // orijinal commitment
    const element_t h_agg                   // aggregateResults[i].h
)
{
    // 1) Girdi elemanlarını non-const kopyalarına çekelim
    //    (proveRes içindeki k G2, c,s1,s2,s3 Zr)
    element_t k_copy, c_copy, s1_copy, s2_copy, s3_copy;
    copyConstElement(k_copy,  proveRes.k,  params.pairing, 2);
    copyConstElement(c_copy,  proveRes.c,  params.pairing, 0);
    copyConstElement(s1_copy, proveRes.s1, params.pairing, 0);
    copyConstElement(s2_copy, proveRes.s2, params.pairing, 0);
    copyConstElement(s3_copy, proveRes.s3, params.pairing, 0);

    // mvk içindeki alpha2, beta2
    element_t alpha2_copy, beta2_copy;
    copyConstElement(alpha2_copy, mvk.alpha2, params.pairing, 2); 
    copyConstElement(beta2_copy,  mvk.beta2,  params.pairing, 2);

    // h_agg -> G1
    element_t h_copy;
    copyConstElement(h_copy, h_agg, params.pairing, 1);

    // com_str -> G1
    element_t com_elem;
    stringToElementG1(com_elem, com_str, params.pairing);

    // 2) (1 - c) hesaplamak için
    element_t one_minus_c;
    element_init_Zr(one_minus_c, params.pairing);
    element_t one;
    element_init_Zr(one, params.pairing);
    element_set1(one);                // one = 1
    element_sub(one_minus_c, one, c_copy);  // one_minus_c = 1 - c

    // 3) Adım 1: k'' = g2^s1 * alpha2^(1-c) * k^c * beta2^s2
    element_t k_prime_prime;
    element_init_G2(k_prime_prime, params.pairing);

    // g2^s1
    element_t g2_s1;
    element_init_G2(g2_s1, params.pairing);
    element_pow_zn(g2_s1, params.g2, s1_copy);

    // alpha2^(1-c)
    element_t alpha2_pow;
    element_init_G2(alpha2_pow, params.pairing);
    element_pow_zn(alpha2_pow, alpha2_copy, one_minus_c);

    // k^c
    element_t k_pow_c;
    element_init_G2(k_pow_c, params.pairing);
    element_pow_zn(k_pow_c, k_copy, c_copy);

    // beta2^s2
    element_t beta2_s2;
    element_init_G2(beta2_s2, params.pairing);
    element_pow_zn(beta2_s2, beta2_copy, s2_copy);

    // k_prime_prime = g2^s1
    element_set(k_prime_prime, g2_s1);
    // multiply by alpha2^(1-c)
    element_mul(k_prime_prime, k_prime_prime, alpha2_pow);
    // multiply by k^c
    element_mul(k_prime_prime, k_prime_prime, k_pow_c);
    // multiply by beta2^s2
    element_mul(k_prime_prime, k_prime_prime, beta2_s2);

    // 4) Adım 2: com'' = g1^s3 * h^s2 * com^c
    element_t com_prime_prime;
    element_init_G1(com_prime_prime, params.pairing);

    // g1^s3
    element_t g1_s3;
    element_init_G1(g1_s3, params.pairing);
    element_pow_zn(g1_s3, params.g1, s3_copy);

    // h^s2
    element_t h_s2;
    element_init_G1(h_s2, params.pairing);
    element_pow_zn(h_s2, h_copy, s2_copy);

    // com^c
    element_t com_pow_c;
    element_init_G1(com_pow_c, params.pairing);
    element_pow_zn(com_pow_c, com_elem, c_copy);

    // com'' = g1^s3 * h^s2 * com^c
    element_set(com_prime_prime, g1_s3);
    element_mul(com_prime_prime, com_prime_prime, h_s2);
    element_mul(com_prime_prime, com_prime_prime, com_pow_c);

    // 5) Adım 3: c' = Hash(g1, g2, h, com, com'', k, k'')
    //    (generateKoRProof içindeki sıra ile aynı olmalı)
    std::ostringstream hashOSS;
    hashOSS << elementToHexStr(params.g1)
            << elementToHexStr(params.g2)
            << elementToHexStr(h_copy)
            << elementToHexStr(com_elem)
            << elementToHexStr(com_prime_prime)
            << elementToHexStr(k_copy)
            << elementToHexStr(k_prime_prime);

    std::string hashInput = hashOSS.str();

    // SHA-512 al
    unsigned char hashDigest[SHA512_DIGEST_LENGTH];
    SHA512(reinterpret_cast<const unsigned char*>(hashInput.data()), hashInput.size(), hashDigest);

    // Hex
    std::ostringstream hashFinalOSS;
    hashFinalOSS << std::hex << std::setfill('0');
    for (int i = 0; i < SHA512_DIGEST_LENGTH; i++) {
        hashFinalOSS << std::setw(2) << (int)hashDigest[i];
    }
    std::string c_prime_hex = hashFinalOSS.str();

    // c' -> mpz -> element
    mpz_t c_prime_mpz;
    mpz_init(c_prime_mpz);
    if (mpz_set_str(c_prime_mpz, c_prime_hex.c_str(), 16) != 0) {
        mpz_clear(c_prime_mpz);
        // Temizliği yapıp return false
        element_clear(k_copy); element_clear(c_copy); element_clear(s1_copy);
        element_clear(s2_copy); element_clear(s3_copy);
        element_clear(alpha2_copy); element_clear(beta2_copy);
        element_clear(h_copy); element_clear(com_elem);
        element_clear(one_minus_c); element_clear(one);
        element_clear(k_prime_prime); element_clear(g2_s1);
        element_clear(alpha2_pow); element_clear(k_pow_c);
        element_clear(beta2_s2); element_clear(com_prime_prime);
        element_clear(g1_s3); element_clear(h_s2);
        element_clear(com_pow_c);
        return false;
    }
    // mod p
    mpz_mod(c_prime_mpz, c_prime_mpz, params.prime_order);
    element_t c_prime;
    element_init_Zr(c_prime, params.pairing);
    element_set_mpz(c_prime, c_prime_mpz);
    mpz_clear(c_prime_mpz);

    // 6) Adım 4: c' == c ?
    bool isEqual = (element_cmp(c_prime, c_copy) == 0);

    // Bellek temizliği
    element_clear(k_copy);
    element_clear(c_copy);
    element_clear(s1_copy);
    element_clear(s2_copy);
    element_clear(s3_copy);
    element_clear(alpha2_copy);
    element_clear(beta2_copy);
    element_clear(h_copy);
    element_clear(com_elem);
    element_clear(one_minus_c);
    element_clear(one);
    element_clear(k_prime_prime);
    element_clear(g2_s1);
    element_clear(alpha2_pow);
    element_clear(k_pow_c);
    element_clear(beta2_s2);
    element_clear(com_prime_prime);
    element_clear(g1_s3);
    element_clear(h_s2);
    element_clear(com_pow_c);
    element_clear(c_prime);

    return isEqual; // c' != c ise false, eşitse true
}
