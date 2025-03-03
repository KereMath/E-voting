#ifndef AGGREGATE_H
#define AGGREGATE_H

#include "setup.h"
#include "unblindsign.h" // for UnblindSignature
#include <vector>
#include <stdexcept>

/*
  The partial unblinded signature structure: (h, sm)
  Already in unblindsign.h => UnblindSignature

  We define an 'AggregateInput' and 'AggregateOutput' to unify the logic of
  combining partial unblinded signatures.

  'AggregateInput':
    - partials:  The partial unblinded sigs => vector<UnblindSignature>
    - alpha2, beta2, beta1 => the MASTER public key: (g2^x, g2^y, g1^y)
    - DIDi => mpz_t for the user identity
*/
struct AggregateInput {
    std::vector<UnblindSignature> partials; 
    element_t alpha2; // G2
    element_t beta2;  // G2
    element_t beta1;  // G1
    mpz_t DIDi;       // the user's DID
};

struct AggregateOutput {
    element_t h; // G1
    element_t s; // G1
};

/*
  aggregateSignatures: implements Alg.14
   Girdi: partial unblinded sigs (h, sm), mvk=(alpha2, beta2, beta1)
   Çıktı: final sig = (h, s), where s=product of all partial sm in G1
*/
AggregateOutput aggregateSignatures(
    TIACParams &params,
    const AggregateInput &in
);

#endif // AGGREGATE_H
