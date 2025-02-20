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

// canonicalElementToHex: Bir element'in kanonik bayt dizisini alıp hex string'e çevirir.
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

// normalizeElement: Bir element'i canonicalElementToHex ile normalize edip, yeniden element'e yükler.
inline void normalizeElement(element_t e) {
    std::string hex = canonicalElementToHex(e);
    // Bu, elemanın dahili temsilini hex üzerinden yeniden oluşturur.
    element_set_str(e, hex.c_str(), 16);
}

// sha512Hex: Verilen stringi SHA-512 ile hash'ler, sonucu hex string olarak döndürür.
inline std::string sha512Hex(const std::string &input) {
    unsigned char hash[SHA512_DIGEST_LENGTH];
    SHA512(reinterpret_cast<const unsigned char*>(input.c_str()), input.size(), hash);
    std::stringstream ss;
    for (int i = 0; i < SHA512_DIGEST_LENGTH; i++) {
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
    }
    return ss.str();
}

// hashStringToZr: Verilen stringi hash'ler ve Zₚ elemanı olarak result'a aktarır.
inline void hashStringToZr(const std::string &input, TIACParams &params, element_t result) {
    std::string hexStr = sha512Hex(input);
    mpz_t num;
    mpz_init(num);
    mpz_set_str(num, hexStr.c_str(), 16);
    mpz_mod(num, num, params.pairing->r);
    element_set_mpz(result, num);
    mpz_clear(num);
}

// hashVectorToZr: Bir string vektöründeki verileri birleştirip, hashStringToZr ile Zₚ elemanı olarak result'a aktarır.
inline void hashVectorToZr(const std::vector<std::string> &data, TIACParams &params, element_t result) {
    std::stringstream ss;
    for (const auto &s : data)
        ss << s;
    hashStringToZr(ss.str(), params, result);
}

// hashToG1: Verilen stringi hash'leyip, g1 üzerinden G₁ elemanı üretir.
inline void hashToG1(const std::string &input, TIACParams &params, element_t output) {
    element_t hashZr;
    element_init_Zr(hashZr, params.pairing);
    hashStringToZr(input, params, hashZr);
    element_init_G1(output, params.pairing);
    element_pow_zn(output, params.g1, hashZr);
    element_clear(hashZr);
}

#endif // COMMON_UTILS_H
