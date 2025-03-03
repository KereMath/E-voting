#ifndef AGGREGATE_H
#define AGGREGATE_H

#include "setup.h"
#include "unblindsign.h"
#include <vector>

/*
  partial unblinded sig => (h, sm)
  We'll combine them.

  'AggregateInput':
    partials => a vector of UnblindSignature
    alpha2, beta2, beta1 => the MASTER public key
    DIDi => mpz for DID
*/
struct AggregateInput {
    std::vector<UnblindSignature> partials;  // each is (h, sm)
    element_t alpha2;                        // G2 (non-const)
    element_t beta2;                         // G2
    element_t beta1;                         // G1
    mpz_t     DIDi;                          // non-const mpz
};

struct AggregateOutput {
    element_t h; // G1
    element_t s; // G1
};

/*
  aggregateSignatures => merges partial unblinded sigs (h, s_m)
                         into one final (h, s)
*/
AggregateOutput aggregateSignatures(
    TIACParams &params,
    AggregateInput &in  // pass by non-const reference
);

#endif // AGGREGATE_H
