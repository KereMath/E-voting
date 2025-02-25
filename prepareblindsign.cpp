#include "prepareblindsign.h"
#include <openssl/sha.h>
#include <vector>
#include <random>
#include <sstream>
#include <iomanip>
#include <stdexcept>
#include <omp.h>  // OpenMP ekledik 🚀

// Rastgele Zr üretimi
static inline void randomZr(element_t zr, TIACParams &params) {
    element_random(zr);
}

// DID (hex) -> mpz mod p
static inline void didStringToMpz(const std::string &didStr, mpz_t rop, const mpz_t p) {
    mpz_set_str(rop, didStr.c_str(), 16);
    mpz_mod(rop, rop, p);
}

// G1 elemanını hex string’e çevir (Optimize edilmiş)
static inline std::string elementToStringG1(element_s *elemPtr) {
    int length = element_length_in_bytes(elemPtr);
    std::vector<unsigned char> buf(length);
    element_to_bytes(buf.data(), elemPtr);

    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (auto c : buf) {
        oss << std::setw(2) << (int)c;
    }
    return oss.str();
}

// Hash fonksiyonunu G1 elemanına dönüştür (Optimize)
static inline void hashToG1(element_t outG1, TIACParams &params, element_t inElem) {
    std::string s = elementToStringG1(inElem);
    element_from_hash(outG1, s.data(), s.size());
}

// Daha hızlı Zr hashleme (SHA-512 yerine SHA-256 kullanıldı)
static inline void hashToZr(element_t outZr, TIACParams &params, const std::vector<element_s*> &elems) {
    std::ostringstream oss;
    for (auto ePtr : elems) {
        oss << elementToStringG1(ePtr);
    }
    std::string msg = oss.str();
    
    unsigned char digest[SHA256_DIGEST_LENGTH];  // SHA-512 yerine SHA-256
    SHA256((unsigned char*)msg.data(), msg.size(), digest);

    mpz_t tmp;
    mpz_init(tmp);
    mpz_import(tmp, SHA256_DIGEST_LENGTH, 1, 1, 0, 0, digest);
    mpz_mod(tmp, tmp, params.prime_order);
    element_set_mpz(outZr, tmp);
    mpz_clear(tmp);
}

/* 🏎️ Daha Hızlı prepareBlindSign */
PrepareBlindSignOutput prepareBlindSign(TIACParams &params, const std::string &didStr) {
    PrepareBlindSignOutput out;
    mpz_t oi, o, didInt;
    mpz_inits(oi, o, didInt, NULL);

    // Rastgele oi ve o hesapla
    #pragma omp parallel sections  // OpenMP ile paralelleştirildi 🚀
    {
        #pragma omp section
        {
            element_t tmp;
            element_init_Zr(tmp, params.pairing);
            element_random(tmp);
            element_to_mpz(oi, tmp);
            element_clear(tmp);
        }
        #pragma omp section
        {
            element_t tmp;
            element_init_Zr(tmp, params.pairing);
            element_random(tmp);
            element_to_mpz(o, tmp);
            element_clear(tmp);
        }
    }

    // DID string -> mpz
    didStringToMpz(didStr, didInt, params.prime_order);

    // comi = g1^oi * h1^did
    element_init_G1(out.comi, params.pairing);
    {
        element_t g1_oi, h1_did;
        element_init_G1(g1_oi, params.pairing);
        element_init_G1(h1_did, params.pairing);

        #pragma omp parallel sections
        {
            #pragma omp section
            {
                element_t exp;
                element_init_Zr(exp, params.pairing);
                element_set_mpz(exp, oi);
                element_pow_zn(g1_oi, params.g1, exp);
                element_clear(exp);
            }
            #pragma omp section
            {
                element_t exp;
                element_init_Zr(exp, params.pairing);
                element_set_mpz(exp, didInt);
                element_pow_zn(h1_did, params.h1, exp);
                element_clear(exp);
            }
        }

        element_mul(out.comi, g1_oi, h1_did);
        element_clear(g1_oi);
        element_clear(h1_did);
    }

    // h = HashInG1(comi)
    element_init_G1(out.h, params.pairing);
    hashToG1(out.h, params, out.comi);

    // com = g1^o * h^did
    element_init_G1(out.com, params.pairing);
    {
        element_t g1_o, h_did;
        element_init_G1(g1_o, params.pairing);
        element_init_G1(h_did, params.pairing);

        #pragma omp parallel sections
        {
            #pragma omp section
            {
                element_t exp;
                element_init_Zr(exp, params.pairing);
                element_set_mpz(exp, o);
                element_pow_zn(g1_o, params.g1, exp);
                element_clear(exp);
            }
            #pragma omp section
            {
                element_t exp;
                element_init_Zr(exp, params.pairing);
                element_set_mpz(exp, didInt);
                element_pow_zn(h_did, out.h, exp);
                element_clear(exp);
            }
        }

        element_mul(out.com, g1_o, h_did);
        element_clear(g1_o);
        element_clear(h_did);
    }

    // KoR Proof hesapla (Çoklu thread'lerle hızlandırıldı)
    out.pi_s = computeKoR(params, out.com, out.comi, params.g1, params.h1, out.h, oi, didInt, o);

    // "o" değerini de output içinde sakla
    mpz_init(out.o);
    mpz_set(out.o, o);

    // Temizlik
    mpz_clears(oi, o, didInt, NULL);

    return out;
}
