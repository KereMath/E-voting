#include "keygen.h"
#include <iostream>
#include <vector>
#include <random>
#include <stdexcept>
#include <tbb/parallel_for.h>
#include <tbb/global_control.h>

// MPZWrapper: mpz_t’yi RAII biçiminde yöneten basit wrapper.
class MPZWrapper {
public:
    mpz_t value;
    MPZWrapper() { mpz_init(value); }
    MPZWrapper(const MPZWrapper &other) {
        mpz_init(value);
        mpz_set(value, other.value);
    }
    MPZWrapper& operator=(const MPZWrapper &other) {
        if (this != &other) {
            mpz_set(value, other.value);
        }
        return *this;
    }
    ~MPZWrapper() { mpz_clear(value); }
};

// [0, p-1] aralığında rastgele MPZWrapper üretir.
static void random_mpz_modp(MPZWrapper &rop, const mpz_t p) {
    static std::random_device rd;
    static std::mt19937_64 gen(rd());
    size_t bits = mpz_sizeinbase(p, 2);
    size_t bytes = (bits + 7) / 8;
    std::vector<unsigned char> buf(bytes);
    for (size_t i = 0; i < bytes; i++) {
        buf[i] = static_cast<unsigned char>(gen() & 0xFF);
    }
    mpz_import(rop.value, bytes, 1, 1, 0, 0, buf.data());
    mpz_mod(rop.value, rop.value, p);
}

// t adet (t-1) dereceli polinom katsayılarını [0, p-1] rastgele seç (MPZWrapper kullanarak).
static void randomPolynomial(std::vector<MPZWrapper> &poly, int t, const mpz_t p) {
    poly.resize(t);
    for (int i = 0; i < t; i++) {
        random_mpz_modp(poly[i], p);
    }
}

// poly(x) = sum_{k=0}^{t-1} [ poly[k] * x^k ] mod p.
static void evalPolynomial(mpz_t result, const std::vector<MPZWrapper> &poly, int xValue, const mpz_t p) {
    mpz_set_ui(result, 0);
    mpz_t term, xPow;
    mpz_init(term);
    mpz_init_set_ui(xPow, 1); // x^0 = 1
    for (size_t k = 0; k < poly.size(); k++) {
        mpz_mul(term, poly[k].value, xPow);
        mpz_add(result, result, term);
        mpz_mod(result, result, p);
        mpz_mul_ui(xPow, xPow, xValue);
        mpz_mod(xPow, xPow, p);
    }
    mpz_clear(term);
    mpz_clear(xPow);
}

// Algoritma 2: Coconut TTP ile Anahtar Üretimi
KeyGenOutput keygen(TIACParams &params, int t, int ne) {
    KeyGenOutput keyOut;
    keyOut.eaKeys.resize(ne);

    // vPoly ve wPoly polinom katsayılarını üret.
    std::vector<MPZWrapper> vPoly, wPoly;
    randomPolynomial(vPoly, t, params.prime_order);
    randomPolynomial(wPoly, t, params.prime_order);

    // v(0) -> x, w(0) -> y
    mpz_t x, y;
    mpz_init(x);
    mpz_init(y);
    evalPolynomial(x, vPoly, 0, params.prime_order);
    evalPolynomial(y, wPoly, 0, params.prime_order);

    // mvk elemanlarını initialize et.
    element_init_G2(keyOut.mvk.alpha2, params.pairing);
    element_init_G2(keyOut.mvk.beta2, params.pairing);
    element_init_G1(keyOut.mvk.beta1, params.pairing);

    // x,y'yi element'e dönüştür.
    element_t expX, expY;
    element_init_Zr(expX, params.pairing);
    element_init_Zr(expY, params.pairing);
    element_set_mpz(expX, x);
    element_set_mpz(expY, y);

    element_pow_zn(keyOut.mvk.alpha2, params.g2, expX);
    element_pow_zn(keyOut.mvk.beta2, params.g2, expY);
    element_pow_zn(keyOut.mvk.beta1, params.g1, expY);

    // EA otoriteleri hesaplamasını paralelleştiriyoruz.
    unsigned int numThreads = std::thread::hardware_concurrency();
    if (numThreads == 0) numThreads = 4;
    tbb::global_control gc(tbb::global_control::max_allowed_parallelism, numThreads);
    tbb::parallel_for(0, ne, [&](int m_index) {
        int m = m_index + 1;
        mpz_t xm, ym;
        mpz_init(xm);
        mpz_init(ym);
        evalPolynomial(xm, vPoly, m, params.prime_order);
        evalPolynomial(ym, wPoly, m, params.prime_order);
        element_set_mpz(keyOut.eaKeys[m_index].sgk1, xm);
        element_set_mpz(keyOut.eaKeys[m_index].sgk2, ym);
        element_t expXm, expYm;
        element_init_Zr(expXm, params.pairing);
        element_init_Zr(expYm, params.pairing);
        element_set_mpz(expXm, xm);
        element_set_mpz(expYm, ym);
        element_pow_zn(keyOut.eaKeys[m_index].vkm1, params.g2, expXm);
        element_pow_zn(keyOut.eaKeys[m_index].vkm2, params.g2, expYm);
        element_pow_zn(keyOut.eaKeys[m_index].vkm3, params.g1, expYm);
        element_clear(expXm);
        element_clear(expYm);
        mpz_clear(xm);
        mpz_clear(ym);
    });

    // Temizlik: MPZWrapper'lar otomatik temizlenecek.
    mpz_clear(x);
    mpz_clear(y);
    element_clear(expX);
    element_clear(expY);

    return keyOut;
}
