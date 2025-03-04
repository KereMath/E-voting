#ifndef PROVE_CREDENTIAL_H
#define PROVE_CREDENTIAL_H

#include "aggregate.h"  // AggregateSignature, MasterVerKey
#include "setup.h"      // TIACParams
#include <string>

struct ProveCredentialSigmaRnd {
    element_t h;  // h'' ∈ G₁
    element_t s;  // s'' ∈ G₁
    std::string debug_info;  // Debug için ara çıktılar
};

struct ProveCredentialOutput {
    ProveCredentialSigmaRnd sigmaRnd; // σRnd = (h'', s'')
    element_t k;                      // k = α₂ · (β₂)^(DID) · g₂^(r₂)
    std::string proof_v;              // KoR ispatı: π_v = (c, s₁, s₂, s₃) tuple'ı (string olarak)
};

ProveCredentialOutput proveCredential(
    TIACParams &params,
    AggregateSignature &aggSig,
    MasterVerKey &mvk,
    const std::string &didStr
);

#endif
