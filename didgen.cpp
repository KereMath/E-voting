#include "didgen.h"
#include <openssl/sha.h>  // SHA512 için
#include <iomanip>
#include <sstream>
#include <vector>
#include <random>
#include <stdexcept>

// Yardımcı fonksiyon: rastgele mpz üret (0 <= rop < p)
static void random_mpz_modp(mpz_t rop, const mpz_t p) {
    static std::random_device rd;
    static std::mt19937_64 gen(rd());

    size_t bits = mpz_sizeinbase(p, 2);
    size_t bytes = (bits+7)/8; 
    std::vector<unsigned char> buf(bytes);

    for(size_t i=0; i<bytes; i++) {
        buf[i] = static_cast<unsigned char>(gen() & 0xFF);
    }

    mpz_import(rop, bytes, 1, 1, 0, 0, buf.data());
    mpz_mod(rop, rop, p);
}

// Yardımcı fonksiyon: girilen veriyi (string) SHA-512 ile özetleyip hex string döndürür
static std::string sha512_hex(const std::string &input) {
    unsigned char hash[SHA512_DIGEST_LENGTH];
    SHA512((const unsigned char*)input.data(), input.size(), hash);

    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for(size_t i = 0; i < SHA512_DIGEST_LENGTH; i++) {
        oss << std::setw(2) << (int)hash[i];
    }
    return oss.str();
}

// createDID fonksiyonu
DID createDID(const TIACParams &params, const std::string &userID) {
    DID result;
    mpz_init(result.x);

    // 1) Rastgele x
    random_mpz_modp(result.x, params.prime_order);

    // 2) x'i string'e dönüştür
    char* x_str = mpz_get_str(nullptr, 10, result.x);

    // 3) userID + x_str birleştir
    std::string concat_str = userID + x_str;

    // 4) SHA-512 ile özet al
    result.did = sha512_hex(concat_str);

    // Bellek
    free(x_str);

    return result;
}
