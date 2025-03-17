#include "checkkorverify.h"
#include <openssl/sha.h>
#include <sstream>
#include <iomanip>
#include <vector>
#include <stdexcept>
#include <iostream>


static void copyConstElement(element_t dest, const element_t src, pairing_t pairing, int element_type) {
    switch (element_type) {
        case 1: 
            element_init_G1(dest, pairing);
            break;
        case 2: 
            element_init_G2(dest, pairing);
            break;
        default: 
            element_init_Zr(dest, pairing);
            break;
    }
    element_t temp;
    temp[0] = *((element_s*)(&src[0]));
    element_set(dest, temp);
}


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


static std::string elementToHexStr(const element_t elem) {
    element_t tmp;
    tmp[0] = *((element_s*)(&elem[0]));
    int len = element_length_in_bytes(tmp);
    std::vector<unsigned char> buf(len);
    element_to_bytes(buf.data(), tmp);
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (unsigned char c : buf) {
        oss << std::setw(2) << (int)c;
    }
    return oss.str();
}


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


bool checkKoRVerify(TIACParams &params,const ProveCredentialOutput &proveRes,const MasterVerKey &mvk, const std::string &com_str, const element_t h_agg){
    element_t k_copy, c_copy, s1_copy, s2_copy, s3_copy;
    copyConstElement(k_copy,  proveRes.k,  params.pairing, 2);
    copyConstElement(c_copy,  proveRes.c,  params.pairing, 0);
    copyConstElement(s1_copy, proveRes.s1, params.pairing, 0);
    copyConstElement(s2_copy, proveRes.s2, params.pairing, 0);
    copyConstElement(s3_copy, proveRes.s3, params.pairing, 0);
    element_t alpha2_copy, beta2_copy;
    copyConstElement(alpha2_copy, mvk.alpha2, params.pairing, 2); 
    copyConstElement(beta2_copy,  mvk.beta2,  params.pairing, 2);
    element_t h_copy;
    copyConstElement(h_copy, h_agg, params.pairing, 1);
    element_t com_elem;
    stringToElementG1(com_elem, com_str, params.pairing);
    element_t one_minus_c;
    element_init_Zr(one_minus_c, params.pairing);
    element_t one;
    element_init_Zr(one, params.pairing);
    element_set1(one);               
    element_sub(one_minus_c, one, c_copy);  
    element_t k_prime_prime;
    element_init_G2(k_prime_prime, params.pairing);
    element_t g2_s1;
    element_init_G2(g2_s1, params.pairing);
    element_pow_zn(g2_s1, params.g2, s1_copy);
    element_t alpha2_pow;
    element_init_G2(alpha2_pow, params.pairing);
    element_pow_zn(alpha2_pow, alpha2_copy, one_minus_c);
    element_t k_pow_c;
    element_init_G2(k_pow_c, params.pairing);
    element_pow_zn(k_pow_c, k_copy, c_copy);
    element_t beta2_s2;
    element_init_G2(beta2_s2, params.pairing);
    element_pow_zn(beta2_s2, beta2_copy, s2_copy);
    element_set(k_prime_prime, g2_s1);
    element_mul(k_prime_prime, k_prime_prime, alpha2_pow);
    element_mul(k_prime_prime, k_prime_prime, k_pow_c);
    element_mul(k_prime_prime, k_prime_prime, beta2_s2);
    element_t com_prime_prime;
    element_init_G1(com_prime_prime, params.pairing);
    element_t g1_s3;
    element_init_G1(g1_s3, params.pairing);
    element_pow_zn(g1_s3, params.g1, s3_copy);
    element_t h_s2;
    element_init_G1(h_s2, params.pairing);
    element_pow_zn(h_s2, h_copy, s2_copy);
    element_t com_pow_c;
    element_init_G1(com_pow_c, params.pairing);
    element_pow_zn(com_pow_c, com_elem, c_copy);
    element_set(com_prime_prime, g1_s3);
    element_mul(com_prime_prime, com_prime_prime, h_s2);
    element_mul(com_prime_prime, com_prime_prime, com_pow_c);
    std::ostringstream hashOSS;
    hashOSS << elementToHexStr(params.g1)
            << elementToHexStr(params.g2)
            << elementToHexStr(h_copy)
            << elementToHexStr(com_elem)
            << elementToHexStr(com_prime_prime)
            << elementToHexStr(k_copy)
            << elementToHexStr(k_prime_prime);
    std::string hashInput = hashOSS.str();
    unsigned char hashDigest[SHA512_DIGEST_LENGTH];
    SHA512(reinterpret_cast<const unsigned char*>(hashInput.data()), hashInput.size(), hashDigest);
    std::ostringstream hashFinalOSS;
    hashFinalOSS << std::hex << std::setfill('0');
    for (int i = 0; i < SHA512_DIGEST_LENGTH; i++) {
        hashFinalOSS << std::setw(2) << (int)hashDigest[i];
    }
    std::string c_prime_hex = hashFinalOSS.str();
    mpz_t c_prime_mpz;
    mpz_init(c_prime_mpz);
    if (mpz_set_str(c_prime_mpz, c_prime_hex.c_str(), 16) != 0) {
        mpz_clear(c_prime_mpz);
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
    mpz_mod(c_prime_mpz, c_prime_mpz, params.prime_order);
    element_t c_prime;
    element_init_Zr(c_prime, params.pairing);
    element_set_mpz(c_prime, c_prime_mpz);
    mpz_clear(c_prime_mpz);
    bool isEqual = (element_cmp(c_prime, c_copy) == 0);
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
    return isEqual; 
}
