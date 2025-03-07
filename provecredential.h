#ifndef PROVE_CREDENTIAL_H
#define PROVE_CREDENTIAL_H

#include "aggregate.h"   // For AggregateSignature and MasterVerKey
#include "setup.h"       // For TIACParams
#include <string>
#include <pbc/pbc.h>
#include <gmp.h>

struct ProveCredentialSigmaRnd {
    element_t h; // h'' from σ″
    element_t s; // s'' from σ″
    std::string debug_info;
};

struct ProveCredentialOutput {
    ProveCredentialSigmaRnd sigmaRnd; // σ″ = (h'', s'')
    element_t k;                      // k = α₂ · (β₂)^(did) · g₂^(r)
    
    // Direct storage of proof elements (no parsing needed)
    element_t c;
    element_t s1;
    element_t s2;
    element_t s3;
    
    // Keep the string version for backwards compatibility
    std::string proof_v;              // KoR tuple: (c, s1, s2, s3)
};

ProveCredentialOutput proveCredential(
    TIACParams &params,
    AggregateSignature &aggSig,
    MasterVerKey &mvk,
    const std::string &didStr,
    const mpz_t o   // "o" value from the prepare phase
);

#endif