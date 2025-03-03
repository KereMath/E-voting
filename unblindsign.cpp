#include "unblindsign.h"
#include <stdexcept>
#include <iostream>
#include <chrono>
#include <sstream>
#include <iomanip>
#include <vector>
#include <openssl/sha.h>

// Helper: Convert a G1 element to a hex string.
static std::string elementToHex(element_t e) {
    int len = element_length_in_bytes(e);
    std::vector<unsigned char> buf(len);
    element_to_bytes(buf.data(), e);
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (unsigned char c : buf) {
        oss << std::setw(2) << (int)c;
    }
    return oss.str();
}

// Helper: Compute hcheck = Hash(comi)
static void hashComiToG1(element_t outG1, TIACParams &params, element_t comi) {
    std::string hexStr = elementToHex(comi);
    element_from_hash(outG1, hexStr.data(), hexStr.size());
}

UnblindSignature unblindSignature(
    TIACParams &params,
    UnblindSignInput &in
) {
    auto start = std::chrono::high_resolution_clock::now();

    // Step 1: Verify that Hash(comi) equals h.
    element_t hcheck;
    element_init_G1(hcheck, params.pairing);
    hashComiToG1(hcheck, params, in.comi);
    if (element_cmp(hcheck, in.h) != 0) {
        element_clear(hcheck);
        throw std::runtime_error("unblindSignature(Alg.13): Hash(comi) != h => Hata");
    }
    element_clear(hcheck);

    // Step 2: Compute sm = cm * (β₁)^(-o)
    element_t beta1_pow_o;
    element_init_G1(beta1_pow_o, params.pairing);
    element_t exp_o;
    element_init_Zr(exp_o, params.pairing);
    element_set_mpz(exp_o, in.o);
    element_pow_zn(beta1_pow_o, in.beta1, exp_o); // β₁^o

    element_t inv_beta1_pow_o;
    element_init_G1(inv_beta1_pow_o, params.pairing);
    element_invert(inv_beta1_pow_o, beta1_pow_o); // (β₁)^(-o)

    UnblindSignature result;
    element_init_G1(result.h, params.pairing);
    element_init_G1(result.sm, params.pairing);
    element_set(result.h, in.h);
    element_mul(result.sm, in.cm, inv_beta1_pow_o);

    element_clear(beta1_pow_o);
    element_clear(inv_beta1_pow_o);
    element_clear(exp_o);

    // Step 3: Pairing verification: e(h, α₂ * β₂^(DIDi)) == e(sm, g2)
    element_t left, right;
    element_init_GT(left, params.pairing);
    element_init_GT(right, params.pairing);
    pairing_apply(left, result.h, in.alpha2, params.pairing);
    pairing_apply(right, result.sm, params.g2, params.pairing);

    if (element_cmp(left, right) != 0) {
        throw std::runtime_error("unblindSignature(Alg.13): Pairing dogrulamasi basarisiz => Hata");
    }

    return result;
}
