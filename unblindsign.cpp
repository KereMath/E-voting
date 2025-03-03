#include "unblindsign.h"
#include <stdexcept>
#include <iostream>   // for debug prints
#include <chrono>     // if you want timing
#include <vector>
#include <sstream>
#include <iomanip>
#include <openssl/sha.h>

/*
  Helper: hashComiToG1
    replicate: hcheck = Hash( comi ), using element_from_hash
*/
static void hashComiToG1(element_t outG1, TIACParams &params, element_t comi) {
    // Convert 'comi' (G1) to a canonical byte array
    int len = element_length_in_bytes(comi);
    std::vector<unsigned char> buf(len);
    element_to_bytes(buf.data(), comi);

    // Turn that into a hex string
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (unsigned char c : buf) {
        oss << std::setw(2) << (int)c;
    }
    std::string data = oss.str();

    // Then map to G1
    element_from_hash(outG1, data.data(), data.size());
}

UnblindSignature unblindSignature(
    TIACParams &params,
    UnblindSignInput &in
) {
    // optional: measure time
    auto start = std::chrono::high_resolution_clock::now();

    // 1) if Hash(comi) != h => error
    element_t hcheck;
    element_init_G1(hcheck, params.pairing);
    hashComiToG1(hcheck, params, in.comi);

    if (element_cmp(hcheck, in.h) != 0) {
        element_clear(hcheck);
        throw std::runtime_error("unblindSignature(Alg.13): Hash(comi) != h => Hata");
    }
    element_clear(hcheck);

    // 2) sm = cm * (beta1^(-o))

    // (a) beta1^o
    element_t beta1_pow_o;
    element_init_G1(beta1_pow_o, params.pairing);

    element_t exp_o;
    element_init_Zr(exp_o, params.pairing);
    element_set_mpz(exp_o, in.o);  // in.o is mpz, convert to element

    element_pow_zn(beta1_pow_o, in.beta1, exp_o); // beta1^o

    // (b) invert
    element_t inv_beta1_pow_o;
    element_init_G1(inv_beta1_pow_o, params.pairing);
    element_invert(inv_beta1_pow_o, beta1_pow_o);

    // (c) sm = cm * inv_beta1_pow_o
    UnblindSignature result;
    element_init_G1(result.h,  params.pairing);
    element_init_G1(result.sm, params.pairing);

    element_set(result.h, in.h);
    element_mul(result.sm, in.cm, inv_beta1_pow_o);

    // cleanup
    element_clear(beta1_pow_o);
    element_clear(inv_beta1_pow_o);
    element_clear(exp_o);

    // 3) pairing check: e(h, alpha2 * beta2^DIDi) == e(sm, g2) ?
    element_t beta2_pow_did;
    element_init_G2(beta2_pow_did, params.pairing);

    element_t exp_did;
    element_init_Zr(exp_did, params.pairing);
    element_set_mpz(exp_did, in.DIDi);

    element_pow_zn(beta2_pow_did, in.beta2, exp_did); // beta2^(DIDi)

    element_t combined;
    element_init_G2(combined, params.pairing);
    element_mul(combined, in.alpha2, beta2_pow_did);  // alpha2 * beta2^(DIDi)

    element_t left, right;
    element_init_GT(left,  params.pairing);
    element_init_GT(right, params.pairing);

    pairing_apply(left,  result.h,  combined,  params.pairing); // e(h, combined)
    pairing_apply(right, result.sm, params.g2, params.pairing); // e(sm, g2)

    bool ok = (element_cmp(left, right) == 0);

    // cleanup
    element_clear(beta2_pow_did);
    element_clear(combined);
    element_clear(left);
    element_clear(right);
    element_clear(exp_did);

    if (!ok) {
        // free result
        element_clear(result.h);
        element_clear(result.sm);
        throw std::runtime_error("unblindSignature(Alg.13): Pairing dogrulamasi basarisiz => Hata");
    }

    auto end = std::chrono::high_resolution_clock::now();
    auto ms  = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();
    std::cout << "[DEBUG] unblindSignature took ~" << (ms/1000.0) << " ms\n";

    // Return (h, sm)
    return result;
}
