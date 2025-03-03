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
    std::vector<UnblindSignature> partials;
    element_t alpha2; // G2
    element_t beta2;  // G2
    element_t beta1;  // G1
    mpz_t     DIDi;   // Zr
};

struct AggregateOutput {
    element_t h; // G1
    element_t s; // G1
};

/*
  aggregateSignatures => Alg.14
*/
AggregateOutput aggregateSignatures(
    TIACParams &params,
    const AggregateInput &in
);

#endif // AGGREGATE_H
