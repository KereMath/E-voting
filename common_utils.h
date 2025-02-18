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

// elementToStr: Bir element'in string temsilini döndürür.
inline std::string elementToStr(element_t e) {
    char buffer[1024];
    element_snprintf(buffer, sizeof(buffer), "%B", e);
    return std::string(buffer);
}

// sha512Hex: Verilen stringi SHA-512 ile hash'ler, sonucu hex formatında döndürür.
inline std::string sha512Hex(const std::string &input) {
    unsigned char hash[SHA512_DIGEST_LENGTH];
    SHA512(reinterpret_cast<const unsigned char*>(input.c_str()), input.size(), hash);
    std::stringstream ss;
    for (int i = 0; i < SHA512_DIGEST_LENGTH; i++) {
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
    }
    return ss.str();
}

// hashStringToZr: Verilen stringi SHA-512 ile hash'ler ve sonucu Zₚ elemanı olarak (params.pairing->r modunda) result'a aktarır.
inline void hashStringToZr(const std::string &input, TIACParams &params, element_t result) {
    std::string hexStr = sha512Hex(input);
    mpz_t num;
    mpz_init(num);
    mpz_set_str(num, hexStr.c_str(), 16);
    mpz_mod(num, num, params.pairing->r);
    element_set_mpz(result, num);
    mpz_clear(num);
}

// hashVectorToZr: Bir string vektöründeki tüm verileri birleştirip, hashStringToZr fonksiyonuyla Zₚ elemanı olarak result'a aktarır.
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
