#ifndef PROVE_CREDENTIAL_H
#define PROVE_CREDENTIAL_H

#include "aggregate.h"  // AggregateSignature, MasterVerKey
#include "setup.h"      // TIACParams
#include <string>

struct ProveCredentialSigmaRnd {
    element_t h;
    element_t s;
    std::string debug_info;
};

struct ProveCredentialOutput {
    ProveCredentialSigmaRnd sigmaRnd; // (h'', s'')
    element_t k;                      // k = α₂ * (β₂)^(DID) * g₂^(r₂)
    std::string proof_v;              // π_v (hash of k)
};

ProveCredentialOutput proveCredential(
    TIACParams &params,
    AggregateSignature &aggSig,
    MasterVerKey &mvk,
    const std::string &didStr
);

#endif
