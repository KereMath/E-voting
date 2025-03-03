#include "unblindsign.h"
#include <stdexcept>
#include <iostream>
#include <chrono>
#include <vector>
#include <sstream>
#include <iomanip>
#include <openssl/sha.h>

static void hashComiToG1(element_t outG1, TIACParams &params, element_t comi) {
    int len = element_length_in_bytes(comi);
    std::vector<unsigned char> buf(len);
    element_to_bytes(buf.data(), comi);

    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (unsigned char c : buf) {
        oss << std::setw(2) << (int)c;
    }
    std::string data = oss.str();

    // map to G1
    element_from_hash(outG1, data.data(), data.size());
}

UnblindSignature unblindSignature(
    TIACParams &params,
    UnblindSignInput &in
) {
    auto start = std::chrono::high_resolution_clock::now();

    // 1) check Hash(comi) == h
    element_t hcheck;
    element_init_G1(hcheck, params.pairing);
    hashComiToG1(hcheck, params, in.comi);

    if (element_cmp(hcheck, in.h) != 0) {
        element_clear(hcheck);
        throw std::runtime_error("unblindSignature(Alg.13): Hash(comi) != h => Hata");
    }
    element_clear(hcheck);

    // 2) sm = cm * (beta1^(-o))
    element_t beta1_pow_o;
    element_init_G1(beta1_pow_o, params.pairing);

    element_t exp_o;
    element_init_Zr(exp_o, params.pairing);
    element_set_mpz(exp_o, in.o);

    element_pow_zn(beta1_pow_o, in.beta1, exp_o);

    element_t inv_beta1_pow_o;
    element_init_G1(inv_beta1_pow_o, params.pairing);
    element_invert(inv_beta1_pow_o, beta1_pow_o);

    UnblindSignature result;
    element_init_G1(result.h,  params.pairing);
    element_init_G1(result.sm, params.pairing);

    element_set(result.h, in.h);
    element_mul(result.sm, in.cm, inv_beta1_pow_o);

    element_clear(beta1_pow_o);
    element_clear(inv_beta1_pow_o);
    element_clear(exp_o);

    // 3) e(h, alpha2 * beta2^DID) == e(sm, g2) ?
    element_t beta2_pow_did;
    element_init_G2(beta2_pow_did, params.pairing);

    element_t exp_did;
    element_init_Zr(exp_did, params.pairing);
    element_set_mpz(exp_did, in.DIDi);

    element_pow_zn(beta2_pow_did, in.beta2, exp_did);

    element_t combined;
    element_init_G2(combined, params.pairing);
    element_mul(combined, in.alpha2, beta2_pow_did);

    element_t left, right;
    element_init_GT(left,  params.pairing);
    element_init_GT(right, params.pairing);

    pairing_apply(left,  result.h, combined, params.pairing);
    pairing_apply(right, result.sm, params.g2, params.pairing);

    bool ok = (element_cmp(left, right) == 0);

    element_clear(beta2_pow_did);
    element_clear(combined);
    element_clear(left);
    element_clear(right);
    element_clear(exp_did);

    if (!ok) {
        element_clear(result.h);
        element_clear(result.sm);
        throw std::runtime_error("unblindSignature(Alg.13): Pairing dogrulamasi basarisiz => Hata");
    }

    auto end = std::chrono::high_resolution_clock::now();
    auto ms  = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();
    std::cout << "[DEBUG] unblindSignature took ~" << (ms/1000.0) << " ms\n";

    return result;
}
