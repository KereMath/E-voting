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
  unblindSignature (Algoritma 13) – Düzeltilmiş:
  Eğer blindSign aşamasında EA ek bir blinding uygulamıyorsa,
  unblinding adımını (β₁^{-o}) atıp doğrudan sm = cm olarak alıyoruz.
  
  1) Eğer Hash(comi) != h, hata.
  2) sm = cm  (yani hiçbir ek faktör uygulanmıyor)
  3) Doğrulama: e(h, α₂ · β₂^(DIDi)) == e(sm, g₂)
  4) Eğer eşit ise σₘ = (h, sm) döndür, aksi halde hata.
*/
UnblindSignature unblindSignature(
    TIACParams &params,
    UnblindSignInput &in
) {
    // 1) Hash(comi) kontrolü:
    element_t hashComi;
    element_init_G1(hashComi, params.pairing);
    {
        std::string s = elemToStrG1(in.comi);
        element_from_hash(hashComi, s.data(), s.size());
    }
    if (element_cmp(hashComi, in.h) != 0) {
        element_clear(hashComi);
        throw std::runtime_error("unblindSignature: Hash(comi) != h => Hata");
    }
    element_clear(hashComi);
    
    // 2) Unblinding: EA blindSign aşamasında ekstra blinding uygulanmadığı için,
    //    sm = in.cm (yani, unblinding adımını atlıyoruz)
    UnblindSignature out;
    element_init_G1(out.h, params.pairing);
    element_init_G1(out.sm, params.pairing);
    element_set(out.h, in.h);
    element_set(out.sm, in.cm);
    
    // 3) Pairing doğrulaması:
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
    
    // Yazdırma: lhs ve rhs değerlerini görmek için
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
