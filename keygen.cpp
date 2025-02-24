#include "keygen.h"
#include <iostream>
#include <vector>
#include <random>
#include <stdexcept>

// Yardımcı fonksiyon: [0, p-1] aralığında rastgele mpz üret
static void random_mpz_modp(mpz_t rop, const mpz_t p) {
    // C++11 random
    static std::random_device rd;
    static std::mt19937_64 gen(rd());

    // p bit uzunluğunda rastgele sayı üretmek için
    // mpz_sizeinbase(p, 2) bitlik bir dağılım yaklaşımı
    size_t bits = mpz_sizeinbase(p, 2);
    // buffer'ı byte cinsinden ayarla
    size_t bytes = (bits+7)/8; 
    std::vector<unsigned char> buf(bytes);

    // Rastgele byte dizisi üret
    for(size_t i=0; i<bytes; i++) {
        buf[i] = static_cast<unsigned char>(gen() & 0xFF);
    }

    // Bu byte dizisini mpz'ye çevir
    mpz_import(rop, bytes, 1, 1, 0, 0, buf.data());
    // Mod al
    mpz_mod(rop, rop, p);
}

// Derecesi (t-1) olan polinomun katsayılarını [0, p-1] rastgele seç
// poly.size() = t -> (t adet katsayı; poly[0], poly[1], ..., poly[t-1])
static void randomPolynomial(std::vector<mpz_t> &poly, int t, const mpz_t p) {
    // her bir mpz_t için init ve rastgele üret
    for(int i=0; i<t; i++) {
        mpz_init(poly[i]);
        random_mpz_modp(poly[i], p);
    }
}

// polinom poly(x) = poly[0] + poly[1]*x + poly[2]*x^2 + ... + poly[t-1]*x^(t-1)
// burada x=point
// result'a mod p olarak poly(point) yazılır
static void evalPolynomial(mpz_t result, const std::vector<mpz_t> &poly, int point, const mpz_t p) {
    mpz_set_ui(result, 0);
    mpz_t term;
    mpz_init(term);

    // point^k hesaplamak için geçici
    mpz_t xPow;
    mpz_init_set_ui(xPow, 1); // x^0 = 1

    for(size_t k = 0; k < poly.size(); k++) {
        // term = poly[k] * (point^k)
        mpz_mul(term, poly[k], xPow);
        mpz_add(result, result, term);
        mpz_mod(result, result, p);

        // sonraki x^k için xPow *= point
        mpz_mul_ui(xPow, xPow, point);
        mpz_mod(xPow, xPow, p);
    }

    mpz_clear(term);
    mpz_clear(xPow);
}

// Algoritma 2: Coconut TTP ile Anahtar Üretimi
KeyGenOutput keygen(const TIACParams &params, int t, int ne) {
    /*
       1) Derecesi (t-1) olan iki polinom v(x), w(x) rastgele seç
       2) msgk = (x, y) = (v(0), w(0))  // master secret
       3) for m in 1..ne:
            sgkm = (xm, ym) = (v(m), w(m)) // EA gizli anahtar
            vkm  = (g2^xm, g2^ym, g1^ym)   // EA doğrulama anahtarı
       4) mvk = (g2^x, g2^y, g1^y)
     */

    KeyGenOutput keyOut;
    keyOut.eaKeys.resize(ne);

    // Polinomlar (t adet katsayı)
    std::vector<mpz_t> vPoly(t), wPoly(t);
    randomPolynomial(vPoly, t, params.prime_order);
    randomPolynomial(wPoly, t, params.prime_order);

    // v(0) -> x, w(0) -> y  (master secret)
    mpz_t x, y;
    mpz_init(x); 
    mpz_init(y);

    evalPolynomial(x, vPoly, 0, params.prime_order);
    evalPolynomial(y, wPoly, 0, params.prime_order);

    // MasterVerKey init
    element_init_G2(keyOut.mvk.alpha2, params.pairing); // g2^x
    element_init_G2(keyOut.mvk.beta2,  params.pairing); // g2^y
    element_init_G1(keyOut.mvk.beta1,  params.pairing); // g1^y

    // exponent için element_t
    element_t expX, expY;
    element_init_Zr(expX, params.pairing);
    element_init_Zr(expY, params.pairing);

    // mpz -> element
    element_set_mpz(expX, x);
    element_set_mpz(expY, y);

    // alpha2 = g2^x
    element_pow_zn(keyOut.mvk.alpha2, params.g2, expX);
    // beta2  = g2^y
    element_pow_zn(keyOut.mvk.beta2,  params.g2, expY);
    // beta1  = g1^y
    element_pow_zn(keyOut.mvk.beta1,  params.g1, expY);

    // Her EA için sgk ve vkm hesaplama
    for(int m=1; m<=ne; m++) {
        // EAKey init
        element_init_Zr(keyOut.eaKeys[m-1].sgk1, params.pairing); // xm
        element_init_Zr(keyOut.eaKeys[m-1].sgk2, params.pairing); // ym
        element_init_G2(keyOut.eaKeys[m-1].vkm1, params.pairing); // g2^(xm)
        element_init_G2(keyOut.eaKeys[m-1].vkm2, params.pairing); // g2^(ym)
        element_init_G1(keyOut.eaKeys[m-1].vkm3, params.pairing); // g1^(ym)

        // v(m) -> xm, w(m) -> ym
        mpz_t xm, ym;
        mpz_init(xm);
        mpz_init(ym);

        evalPolynomial(xm, vPoly, m, params.prime_order);
        evalPolynomial(ym, wPoly, m, params.prime_order);

        // sgk1 = xm, sgk2 = ym (Zr olarak element_set_mpz)
        element_set_mpz(keyOut.eaKeys[m-1].sgk1, xm);
        element_set_mpz(keyOut.eaKeys[m-1].sgk2, ym);

        // exponent'ları geçici elementlere atayalım
        element_t expXm, expYm;
        element_init_Zr(expXm, params.pairing);
        element_init_Zr(expYm, params.pairing);

        element_set_mpz(expXm, xm);
        element_set_mpz(expYm, ym);

        // vkm1 = g2^(xm), vkm2 = g2^(ym), vkm3 = g1^(ym)
        element_pow_zn(keyOut.eaKeys[m-1].vkm1, params.g2, expXm);
        element_pow_zn(keyOut.eaKeys[m-1].vkm2, params.g2, expYm);
        element_pow_zn(keyOut.eaKeys[m-1].vkm3, params.g1, expYm);

        // Temizlik
        element_clear(expXm);
        element_clear(expYm);
        mpz_clear(xm);
        mpz_clear(ym);
    }

    // Polinom katsayılarını temizle
    for(int i=0; i<t; i++) {
        mpz_clear(vPoly[i]);
        mpz_clear(wPoly[i]);
    }

    // x,y ve expX, expY temizliği
    mpz_clear(x);
    mpz_clear(y);
    element_clear(expX);
    element_clear(expY);

    return keyOut;
}
