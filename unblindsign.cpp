#include "unblindsign.h"
#include <openssl/sha.h>
#include <sstream>
#include <iomanip>
#include <stdexcept>
#include <vector>
#include <iostream>

// Yardımcı: G1 elemanını hex string’e çevir (non-const pointer)
static std::string elemToStrG1(element_t g1Elem) {
    int len = element_length_in_bytes(g1Elem);
    std::vector<unsigned char> buf(len);
    element_to_bytes(buf.data(), g1Elem);
    
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (unsigned char c : buf) {
        oss << std::setw(2) << (int)c;
    }
    return oss.str();
}

/*
  unblindSignature (Algoritma 13)
  1) Eğer Hash(comi) != h, hata.
  2) sm = cm * (beta1)^{-o} hesapla.
  3) Doğrulama: e(h, alpha2 * beta2^{DIDi}) == e(sm, g2)
  4) Eğer eşit ise sigma_m = (h, sm) döndür, değilse hata.
*/
UnblindSignature unblindSignature(
    TIACParams &params,
    UnblindSignInput &in
) {
    // 1) Hash(comi) kontrolü
    element_t hashComi;
    element_init_G1(hashComi, params.pairing);
    {
        // comi'yi hex string'e çevirip hash fonksiyonuyla G1'e mapleyelim
        std::string s = elemToStrG1(in.comi);
        element_from_hash(hashComi, s.data(), s.size());
    }
    if(element_cmp(hashComi, in.h) != 0) {
        element_clear(hashComi);
        throw std::runtime_error("unblindSignature: Hash(comi) != h => Hata");
    }
    element_clear(hashComi);

    // 2) sm = cm * beta1^{-o}
    UnblindSignature out;
    element_init_G1(out.h, params.pairing);
    element_init_G1(out.sm, params.pairing);
    
    // out.h = in.h
    element_set(out.h, in.h);
    // out.sm başlangıçta = in.cm
    element_set(out.sm, in.cm);
    
    // Hesapla: beta1^{-o}
    element_t beta1_negO;
    element_init_G1(beta1_negO, params.pairing);
    {
        element_t zrNeg;
        element_init_Zr(zrNeg, params.pairing);
        element_set_mpz(zrNeg, in.o); // in.o: prepareBlindSign'dan saklanan o
        element_neg(zrNeg, zrNeg);    // -o
        element_pow_zn(beta1_negO, in.beta1, zrNeg);
        element_clear(zrNeg);
    }
    // out.sm = out.sm * beta1^{-o}
    element_mul(out.sm, out.sm, beta1_negO);
    element_clear(beta1_negO);

    // 3) Doğrulama: e(h, alpha2 * beta2^{DIDi}) ?= e(sm, g2)
// 3) Doğrulama: e(h, alpha2) == e(sm, g2)
// 3) Doğrulama: e(h, alpha2 * beta2^{DIDi}) ?= e(sm, g2)
element_t alpha2beta;
element_init_G2(alpha2beta, params.pairing);
element_set(alpha2beta, in.alpha2);

element_t beta2_did;
element_init_G2(beta2_did, params.pairing);
{
    element_t didZr;
    element_init_Zr(didZr, params.pairing);
    element_set_mpz(didZr, in.DIDi);
    element_pow_zn(beta2_did, in.beta2, didZr);
    element_clear(didZr);
}
element_mul(alpha2beta, alpha2beta, beta2_did);
element_clear(beta2_did);

element_t lhs;
element_init_GT(lhs, params.pairing);
pairing_apply(lhs, in.h, alpha2beta, params.pairing);
element_clear(alpha2beta);

element_t rhs;
element_init_GT(rhs, params.pairing);
pairing_apply(rhs, out.sm, params.g2, params.pairing);

// Yazdırma: lhs ve rhs GT elemanlarını stringe çeviriyoruz.
char lhsStr[1024], rhsStr[1024];
element_snprintf(lhsStr, sizeof(lhsStr), "%B", lhs);
element_snprintf(rhsStr, sizeof(rhsStr), "%B", rhs);
std::cout << "unblindSignature: lhs = " << lhsStr << "\n";
std::cout << "unblindSignature: rhs = " << rhsStr << "\n";

bool eq = (element_cmp(lhs, rhs) == 0);
element_clear(lhs);
element_clear(rhs);

if (!eq) {
    element_clear(out.h);
    element_clear(out.sm);
    throw std::runtime_error("unblindSignature: pairing mismatch => Hata");
}

    return out;
}
