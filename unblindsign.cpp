#include "unblindsign.h"
#include <openssl/sha.h>
#include <stdexcept>
#include <sstream>
#include <iomanip>
#include <vector>

// Yardımcı: element_t G1 -> hex string
static std::string elemToStrG1(element_t g1Elem) {
    int len = element_length_in_bytes(g1Elem);
    std::vector<unsigned char> buf(len);
    element_to_bytes(buf.data(), g1Elem);

    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for(auto c : buf) {
        oss << std::setw(2) << (int)c;
    }
    return oss.str();
}

/*
  unblindSignature (Alg.13)
   1) if Hash(comi) != h => "Hata"
   2) sm = cm * beta1^{-o}
   3) e(h, alpha2 . beta2^DID) =?= e(sm, g2)
   4) if eq => (h, sm) else => "Hata"
*/
UnblindSignature unblindSignature(
    TIACParams &params,
    const UnblindSignInput &in
) {
    // 1) Hash(comi) != h ?
    element_t hashComi;
    element_init_G1(hashComi, params.pairing);
    {
        // comi -> string
        int len = element_length_in_bytes(in.comi);
        std::vector<unsigned char> buf(len);
        element_to_bytes(buf.data(), in.comi);

        // from_hash
        element_from_hash(hashComi, buf.data(), buf.size());
    }
    if(element_cmp(hashComi, in.h) != 0) {
        element_clear(hashComi);
        throw std::runtime_error("unblindSignature: Hash(comi) != h => Hata");
    }
    element_clear(hashComi);

    // 2) sm = cm * (beta1^{-o}) 
    //  Not: beta1^-o => beta1^( -o mod p ) => xp param 
    UnblindSignature out;
    element_init_G1(out.h,  params.pairing);
    element_init_G1(out.sm, params.pairing);

    // out.h = h
    element_set(out.h, in.h);

    // sm = cm
    element_set(out.sm, in.cm);

    // beta1^{-o}
    element_t beta1_negO;
    element_init_G1(beta1_negO, params.pairing);

    {
        // Zr'de -o (mod p)
        element_t zrNeg;
        element_init_Zr(zrNeg, params.pairing);
        element_set_mpz(zrNeg, in.o); 
        // Eksiye çevirelim
        element_neg(zrNeg, zrNeg); 
        element_pow_zn(beta1_negO, in.beta1, zrNeg);
        element_clear(zrNeg);
    }

    // sm = sm * beta1_negO
    element_mul(out.sm, out.sm, beta1_negO);
    element_clear(beta1_negO);

    // 3) e(h, alpha2 * beta2^DID) =?= e(sm, g2)
    // alpha2 * (beta2^{DID})
    element_t alpha2beta;
    element_init_G2(alpha2beta, params.pairing);
    element_set(alpha2beta, in.alpha2);

    // beta2^DID
    element_t beta2_did;
    element_init_G2(beta2_did, params.pairing);

    {
        element_t didZr;
        element_init_Zr(didZr, params.pairing);
        element_set_mpz(didZr, in.DIDi); // in.DIDi => Zr
        element_pow_zn(beta2_did, in.beta2, didZr);
        element_clear(didZr);
    }

    // alpha2beta *= beta2_did
    element_mul(alpha2beta, alpha2beta, beta2_did);
    element_clear(beta2_did);

    // e(h, alpha2beta)
    element_t lhs;
    element_init_GT(lhs, params.pairing);
    pairing_apply(lhs, in.h, alpha2beta, params.pairing);
    element_clear(alpha2beta);

    // e(sm, g2)
    element_t rhs;
    element_init_GT(rhs, params.pairing);
    pairing_apply(rhs, out.sm, params.g2, params.pairing);

    bool eq = (element_cmp(lhs, rhs) == 0);

    element_clear(lhs);
    element_clear(rhs);

    if(!eq) {
        // e(h, alpha2beta) != e(sm, g2)
        element_clear(out.h);
        element_clear(out.sm);
        throw std::runtime_error("unblindSignature: pairing mismatch => Hata");
    }

    return out; // (h, sm)
}
