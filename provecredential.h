#ifndef PROVE_CREDENTIAL_H
#define PROVE_CREDENTIAL_H

#include "aggregate.h"    // AggregateSignature, MasterVerKey
#include "setup.h"        // TIACParams
#include <string>

// KoR ispatı tuple'sını saklamak için:
struct ProveCredentialKoR {
    std::string c;   // c (Hash sonucu, Zr'de elemanın string gösterimi)
    std::string s1;  // s1 = r1' - c * r1
    std::string s2;  // s2 = r2' - c * DID
    std::string s3;  // s3 = r3' - c * o   (burada o = 0 kabul edilmiştir)
    std::string debug_info; // Tüm ara değerlerin detaylı dökümü
};

// σRnd = (h″, s″)
struct ProveCredentialSigmaRnd {
    element_t h;  // h″ ∈ G1
    element_t s;  // s″ ∈ G1
    std::string debug_info;
};

// Çıktı: σRnd, k ve πᵥ
struct ProveCredentialOutput {
    ProveCredentialSigmaRnd sigmaRnd;  // (h″, s″)
    element_t k;                       // k = α₂ · (β₂)^(DID) · g₂^(r₂)
    ProveCredentialKoR proof_v;        // Tuple: (c, s1, s2, s3)
};

ProveCredentialOutput proveCredential(
    TIACParams &params,
    AggregateSignature &aggSig,
    MasterVerKey &mvk,
    const std::string &didStr
);

#endif
