#ifndef COMMON_UTILS_H
#define COMMON_UTILS_H

#include <pbc/pbc.h>
#include <gmp.h>
#include <string>
#include <vector>
#include <sstream>
#include <iomanip>
#include <openssl/sha.h>
#include "setup.h"
#include <iostream>

inline std::string canonicalElementToHex(element_t e) {
    int size = element_length_in_bytes(e);
    std::vector<unsigned char> buf(size);
    element_to_bytes(buf.data(), e);
    std::stringstream ss;
    for (int i = 0; i < size; i++) {
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)buf[i];
    }
    return ss.str();
}

inline std::string sha512Hex(const std::string& input) {
    unsigned char hash[SHA512_DIGEST_LENGTH];
    SHA512(reinterpret_cast<const unsigned char*>(input.c_str()), input.size(), hash);
    std::stringstream ss;
    for (int i = 0; i < SHA512_DIGEST_LENGTH; i++) {
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
    }
    return ss.str();
}

inline void hashStringToZr(const std::string& input, TIACParams& params, element_t result) {
    std::string hexStr = sha512Hex(input);
    mpz_t num;
    mpz_init(num);
    mpz_set_str(num, hexStr.c_str(), 16);
    mpz_mod(num, num, params.pairing->r);
    element_set_mpz(result, num);
    mpz_clear(num);
    // Debug: Hash sonucunu yazdır
    std::cout << "hashStringToZr - input: " << input << ", hexStr: " << hexStr << std::endl;
    element_printf("hashStringToZr - result = %B\n", result);
}

inline void hashVectorToZr(const std::vector<std::string>& data, TIACParams& params, element_t result) {
    std::stringstream ss;
    for (const auto& s : data)
        ss << s;
    hashStringToZr(ss.str(), params, result);
}

inline void hashToG1(const std::string& input, TIACParams& params, element_t output) {
    element_t hashZr;
    element_init_Zr(hashZr, params.pairing);
    hashStringToZr(input, params, hashZr);
    element_init_G1(output, params.pairing);
    element_pow_zn(output, params.g1, hashZr);
    element_clear(hashZr);
    // Debug: Girdi ve çıktıyı yazdır
    std::cout << "hashToG1 - input: " << input << std::endl;
    element_printf("hashToG1 - output = %B\n", output);
}

#endif // COMMON_UTILS_H