#include "aggregate.h"
#include <stdexcept>
#include <iostream> // for debug prints

AggregateOutput aggregateSignatures(
    TIACParams &params,
    const AggregateInput &in
) {
    // Alg.14 steps:
    // 1) s = 1 in G1
    AggregateOutput out;
    element_init_G1(out.h, params.pairing);
    element_init_G1(out.s, params.pairing);

    if (in.partials.empty()) {
        throw std::runtime_error("aggregateSignatures: no partial signatures!");
    }
    // all partials share the same h, assume partials[0].h
    element_set(out.h, in.partials[0].h);

    element_set1(out.s); // identity in G1

    // 2) for m=1..t => s <- s * s_m
    for (size_t i = 0; i < in.partials.size(); i++) {
        // partial i => (h, s_m)
        element_mul(out.s, out.s, in.partials[i].sm);
    }

    // 3) final = (h, s)
    // 4) optional check:
    //    if e(h, alpha2 * (beta2^DID)) = e(s, g2) => OK else Hata
    {
        // compute beta2^(DID)
        element_t didExp, beta2_pow;
        element_init_Zr(didExp, params.pairing);
        element_init_G2(beta2_pow, params.pairing);

        mpz_t didCopy;
        mpz_init_set(didCopy, in.DIDi);
        element_set_mpz(didExp, didCopy);

        element_pow_zn(beta2_pow, in.beta2, didExp);

        // alpha2 * beta2^DID
        element_t combined;
        element_init_G2(combined, params.pairing);
        element_mul(combined, in.alpha2, beta2_pow);

        // left, right in GT
        element_t left, right;
        element_init_GT(left, params.pairing);
        element_init_GT(right, params.pairing);

        pairing_apply(left, out.h, combined, params.pairing);
        pairing_apply(right, out.s, params.g2, params.pairing);

        bool ok = (element_cmp(left, right) == 0);

        element_clear(didExp);
        element_clear(beta2_pow);
        element_clear(combined);
        element_clear(left);
        element_clear(right);
        mpz_clear(didCopy);

        if (!ok) {
            std::cerr << "aggregateSignatures: final check failed => 'Hata' but continuing\n";
            // Or you could throw if you want:
            // throw std::runtime_error("aggregateSignatures: final check failed!");
        } else {
            std::cout << "[DEBUG] aggregateSignatures: final check => OK!\n";
        }
    }

    return out;
}
