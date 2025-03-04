#ifndef PROVE_CREDENTIAL_H
#define PROVE_CREDENTIAL_H

#include "aggregate.h"  // AggregateSignature, MasterVerKey
#include "setup.h"      // TIACParams
#include <string>

struct ProveCredentialSigmaRnd {
    element_t h;           // h'' = h^(r1)
    element_t s;           // s'' = s^(r1) * (h'')^(r2)
    std::string debug_info;
};

struct ProveCredentialOutput {
    ProveCredentialSigmaRnd sigmaRnd; // (h'', s'')
    element_t k;                      // k = α₂ · (β₂)^(DID) · g₂^(r2)
    std::string proof_v;              // π_v = tuple (c, s1, s2, s3)
};

ProveCredentialOutput proveCredential(
    TIACParams &params,
    AggregateSignature &aggSig,
    MasterVerKey &mvk,
    const std::string &didStr,
    const mpz_t o   // 'o' değeri, prepareBlindSign aşamasından alınan
);

#endif
