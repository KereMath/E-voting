#include "didgen.h"
#include <openssl/sha.h>  
#include <iomanip>
#include <sstream>
#include <vector>
#include <random>
#include <stdexcept>

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

DID createDID(const TIACParams &params, const std::string &userID) {
    DID result;
    mpz_init(result.x);
    random_mpz_modp(result.x, params.prime_order);
    char* x_str = mpz_get_str(nullptr, 10, result.x);
    std::string concat_str = userID + x_str;
    result.did = sha512_hex(concat_str);
    free(x_str);
    return result;
}
