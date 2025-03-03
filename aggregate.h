#ifndef AGGREGATE_H
#define AGGREGATE_H

#include "setup.h"
#include "unblindsign.h"  // for UnblindSignature
#include <vector>

/*
  AggregateInput: 
    - a list of partial unblinded signatures (h, s_m) from each EA
    - mvk: the master verification key = (alpha2, beta2, beta1) = (g2^x, g2^y, g1^y)
    - DIDi for the user
*/
struct AggregateInput {
    std::vector<UnblindSignature> partials; // each is (h, s_m)
    element_t alpha2;  // G2
    element_t beta2;   // G2
    element_t beta1;   // G1
    mpz_t DIDi;        // user DID
};

/*
  AggregateOutput: final signature (h, s) in G1
*/
struct AggregateOutput {
    element_t h;   // G1
    element_t s;   // G1
};

/*
  aggregateSignatures (Alg.14):
    1) s = identity in G1
    2) for each partial sig => multiply s by s_m
    3) final => (h, s)
    4) optionally check e(h, alpha2 * beta2^DID) == e(s, g2)
*/
AggregateOutput aggregateSignatures(
    TIACParams &params,
    const AggregateInput &in
);

#endif // AGGREGATE_H
