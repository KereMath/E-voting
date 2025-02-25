#include "keygen.h"
#include <iostream>
#include <vector>
#include <random>
#include <stdexcept>
#include <tbb/parallel_for.h>
#include <tbb/global_control.h>

// [0, p-1] aralığında rastgele mpz üretir
static void random_mpz_modp(mpz_t rop, const mpz_t p) {
    static std::random_device rd;
    static std::mt19937_64 gen(rd());

    size_t bits = mpz_sizeinbase(p, 2);
    size_t bytes = (bits + 7) / 8;
    std::vector<unsigned char> buf(bytes);

    for (size_t i = 0; i < bytes; i++) {
        buf[i] = static_cast<unsigned char>(gen() & 0xFF);
    }

    mpz_import(rop, bytes, 1, 1, 0, 0, buf.data());
    mpz_mod(rop, rop, p);
}

// Derecesi (t-1) polinom katsayılarını [0, p-1] rastgele seç
// poly.size() = t -> poly[0], ..., poly[t-1]
static void randomPolynomial(std::vector<mpz_t> &poly, int t, const mpz_t p) {
    for (int i = 0; i < t; i++) {
        mpz_init(poly[i]);
        random_mpz_modp(poly[i], p);
    }
}

// poly(x) = sum_{k=0..t-1} [ poly[k] * x^k ] (mod p)
static void evalPolynomial(mpz_t result, const std::vector<mpz_t> &poly,
                           int xValue, const mpz_t p) {
    mpz_set_ui(result, 0);

    mpz_t term;
    mpz_init(term);

    mpz_t xPow;
    mpz_init_set_ui(xPow, 1); // x^0 = 1

    for (size_t k = 0; k < poly.size(); k++) {
        // term = poly[k] * (xValue^k)
        mpz_mul(term, poly[k], xPow);
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

    // Polinom katsayılarını oluştur: vPoly ve wPoly (derece t-1)
    std::vector<mpz_t> vPoly(t), wPoly(t);
    randomPolynomial(vPoly, t, params.prime_order);
    randomPolynomial(wPoly, t, params.prime_order);

    // Ana gizli: x = v(0), y = w(0)
    mpz_t x, y;
    mpz_init(x);
    mpz_init(y);
    evalPolynomial(x, vPoly, 0, params.prime_order);
    evalPolynomial(y, wPoly, 0, params.prime_order);

    // mvk elemanlarını başlatma
    element_init_G2(keyOut.mvk.alpha2, params.pairing);
    element_init_G2(keyOut.mvk.beta2,  params.pairing);
    element_init_G1(keyOut.mvk.beta1,  params.pairing);

    element_t expX, expY;
    element_init_Zr(expX, params.pairing);
    element_init_Zr(expY, params.pairing);
    element_set_mpz(expX, x);
    element_set_mpz(expY, y);

    // mvk.alpha2 = g2^x, mvk.beta2 = g2^y, mvk.beta1 = g1^y
    element_pow_zn(keyOut.mvk.alpha2, params.g2, expX);
    element_pow_zn(keyOut.mvk.beta2, params.g2, expY);
    element_pow_zn(keyOut.mvk.beta1, params.g1, expY);

    // EA otoriteleri anahtar üretimi için paralel döngü (m = 1..ne)
    tbb::parallel_for(1, ne + 1, [&](int m) {
        // keyOut.eaKeys[m-1]'i başlat
        element_init_Zr(keyOut.eaKeys[m - 1].sgk1, params.pairing);
        element_init_Zr(keyOut.eaKeys[m - 1].sgk2, params.pairing);
        element_init_G2(keyOut.eaKeys[m - 1].vkm1, params.pairing);
        element_init_G2(keyOut.eaKeys[m - 1].vkm2, params.pairing);
        element_init_G1(keyOut.eaKeys[m - 1].vkm3, params.pairing);

        mpz_t xm, ym;
        mpz_init(xm);
        mpz_init(ym);

        // v(m) ve w(m) hesaplaması
        evalPolynomial(xm, vPoly, m, params.prime_order);
        evalPolynomial(ym, wPoly, m, params.prime_order);

        // sgk = (xm, ym)
        element_set_mpz(keyOut.eaKeys[m - 1].sgk1, xm);
        element_set_mpz(keyOut.eaKeys[m - 1].sgk2, ym);

        element_t expXm, expYm;
        element_init_Zr(expXm, params.pairing);
        element_init_Zr(expYm, params.pairing);
        element_set_mpz(expXm, xm);
        element_set_mpz(expYm, ym);

        // vkm1 = g2^(xm), vkm2 = g2^(ym), vkm3 = g1^(ym)
        element_pow_zn(keyOut.eaKeys[m - 1].vkm1, params.g2, expXm);
        element_pow_zn(keyOut.eaKeys[m - 1].vkm2, params.g2, expYm);
        element_pow_zn(keyOut.eaKeys[m - 1].vkm3, params.g1, expYm);

        // Temizlik
        element_clear(expXm);
        element_clear(expYm);
        mpz_clear(xm);
        mpz_clear(ym);
    });

    // Polinom katsayılarının temizliği
    for (int i = 0; i < t; i++) {
        mpz_clear(vPoly[i]);
        mpz_clear(wPoly[i]);
    }
    mpz_clear(x);
    mpz_clear(y);
    element_clear(expX);
    element_clear(expY);

    return keyOut;
}