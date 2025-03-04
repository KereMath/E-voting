#ifndef PROVE_CREDENTIAL_H
#define PROVE_CREDENTIAL_H

#include "setup.h"
#include "aggregate.h"
#include "keygen.h"
#include <string>

// ProveCredentialRound: σ'' = (h'', s'')
struct ProveCredentialRound {
    element_t h; // h'' = h^r
    element_t s; // s'' = s^r (Burada s aggregate imzadan alınan s'dir)
    std::string debug_info; // Debug bilgileri (ör. h'' ve s'' değerlerinin string gösterimi)
};

// ProveCredentialOutput: Çıktı olarak imza kanıtı (σRnd, k) ve π_v (hash(k))
struct ProveCredentialOutput {
    ProveCredentialRound sigmaRnd; // σ'' = (h'', s'')
    element_t k;                   // k = α₂ · (β₂)^(DID) · g₂^r
    std::string proof_v;           // π_v = SHA512(k)
};

ProveCredentialOutput proveCredential(TIACParams &params,
                                        AggregateSignature &aggSig,
                                        MasterVerKey &mvk,
                                        const std::string &didStr);

#endif
