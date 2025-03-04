#ifndef PROVE_CREDENTIAL_H
#define PROVE_CREDENTIAL_H

#include "aggregate.h"  // AggregateSignature, MasterVerKey
#include "setup.h"      // TIACParams
#include <string>
#include <gmp.h>
#include <pbc/pbc.h>

// Yapı: ProveCredentialSigmaRnd (σRnd)
struct ProveCredentialSigmaRnd {
    element_t h;              // h'' ∈ G₁
    element_t s;              // s'' ∈ G₁
    std::string debug_info;   // Debug çıktıları
};

// Yapı: ProveCredentialOutput
struct ProveCredentialOutput {
    ProveCredentialSigmaRnd sigmaRnd; // σRnd = (h'', s'')
    element_t k;                      // k = α₂ · (β₂)^(DID) · g₂^(r₂)
    std::string proof_v;              // KoR ispatı: tuple (c, s₁, s₂, s₃) serileştirilmiş hali
};

/// ProveCredential fonksiyonu  
/// @param params: TIAC parametreleri  
/// @param aggSig: Aggregate imza σ = (h, s)  
/// @param mvk: Master Verification Key; burada mvk.alpha2 = α₂, mvk.beta2 = β₂ (β₂, istenildiği üzere)  
/// @param didStr: Seçmenin DID’i (hex string olarak)  
/// @param o: PrepareBlindSign aşamasında üretilen o değeri (mpz_t)  
/// @return ProveCredentialOutput: σRnd, k ve π_v (tuple olarak)  
ProveCredentialOutput proveCredential(
    TIACParams &params,
    AggregateSignature &aggSig,
    MasterVerKey &mvk,
    const std::string &didStr,
    const mpz_t o
);

#endif
