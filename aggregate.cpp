#include "aggregate.h"
#include <stdexcept>
#include <iostream>

AggregateOutput aggregateSignatures(
    TIACParams &params,
    AggregateInput &in
) {
    // 1) s = identity
    AggregateOutput out;
    element_init_G1(out.h, params.pairing);
    element_init_G1(out.s, params.pairing);

    if (in.partials.empty()) {
        throw std::runtime_error("aggregateSignatures: no partial signatures!");
    }

    // partials[0].h is non-const => no error
    element_set(out.h, in.partials[0].h);
    element_set1(out.s);

    // 2) multiply s by each s_m
    for (size_t i = 0; i < in.partials.size(); i++) {
        element_mul(out.s, out.s, in.partials[i].sm);
    }

    // 3) final => (h, s)
    // 4) optional check => e(h, alpha2 * beta2^DID)
    {
        element_t exp_did;
        element_init_Zr(exp_did, params.pairing);
        element_set_mpz(exp_did, in.DIDi);  // DIDi must be mpz_t

        element_t beta2_pow;
        element_init_G2(beta2_pow, params.pairing);
        element_pow_zn(beta2_pow, in.beta2, exp_did); // ok if in.beta2 is non-const

        element_t combined;
        element_init_G2(combined, params.pairing);
        element_mul(combined, in.alpha2, beta2_pow);

        element_t left, right;
        element_init_GT(left, params.pairing);
        element_init_GT(right, params.pairing);

        pairing_apply(left,  out.h, combined, params.pairing);
        pairing_apply(right, out.s, params.g2, params.pairing);

        bool ok = (element_cmp(left, right) == 0);
        if (!ok) {
            std::cerr << "[WARN] aggregateSignatures: final check => failed\n";
        } else {
            std::cout << "[DEBUG] aggregateSignatures: final check => OK!\n";
        }

        // cleanup
        element_clear(exp_did);
        element_clear(beta2_pow);
        element_clear(combined);
        element_clear(left);
        element_clear(right);
    }

    return out;
}
