#include "didgen.h"
#include <openssl/sha.h>  // SHA512 için
#include <iomanip>
#include <sstream>
#include <vector>
#include <random>
#include <stdexcept>

// Thread-safe rastgele sayı üretimi için thread_local kullanımı
static void random_mpz_modp(mpz_t rop, const mpz_t p) {
    thread_local std::random_device rd;
    thread_local std::mt19937_64 gen(rd());

    size_t bits = mpz_sizeinbase(p, 2);
    size_t bytes = (bits + 7) / 8; 
    std::vector<unsigned char> buf(bytes);

    for (size_t i = 0; i < bytes; i++) {
        buf[i] = static_cast<unsigned char>(gen() & 0xFF);
    }

    mpz_import(rop, bytes, 1, 1, 0, 0, buf.data());
    mpz_mod(rop, rop, p);
}

// Girilen string veriyi SHA-512 ile özetleyip hex string döndürür
static std::string sha512_hex(const std::string &input) {
    unsigned char hash[SHA512_DIGEST_LENGTH];
    SHA512(reinterpret_cast<const unsigned char*>(input.data()), input.size(), hash);

    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (size_t i = 0; i < SHA512_DIGEST_LENGTH; i++) {
        oss << std::setw(2) << static_cast<int>(hash[i]);
    }
    return oss.str();
}

// createDID fonksiyonu: Rastgele x üretir, x ve userID'yi birleştirip SHA-512 özetini DID olarak döndürür.
DID createDID(const TIACParams &params, const std::string &userID) {
    DID result;
    mpz_init(result.x);

    // 1) Rastgele x (0 <= x < prime_order)
    random_mpz_modp(result.x, params.prime_order);

    // 2) x'i string'e dönüştür (decimal formatında)
    char* x_str = mpz_get_str(nullptr, 10, result.x);

    // 3) userID ile x_str'yi birleştir
    std::string concat_str = userID + x_str;

    // 4) SHA-512 ile özet al ve DID'yi oluştur
    result.did = sha512_hex(concat_str);

    // Bellek temizliği
    free(x_str);

    return result;
}
