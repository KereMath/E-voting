#ifndef PROVE_CREDENTIAL_H
#define PROVE_CREDENTIAL_H

#include "aggregate.h"    // AggregateSignature, MasterVerKey
#include "setup.h"        // TIACParams
#include <string>
#include <ostream>

// Tuple şeklinde KoR ispatını saklamak için:
struct ProveCredentialKoR {
    std::string c;   // c = hash(g1, g2, h'', com, com', k, k')
    std::string s1;  // s1 = r1' - c · r1
    std::string s2;  // s2 = r2' - c · (DID)
    std::string s3;  // s3 = r3' - c · o   (o: blinding değeri, prepare aşamasından)
    std::string debug_info; // Detaylı ara değer bilgileri
};

// << operatörünü aşırı yükleyelim:
inline std::ostream& operator<<(std::ostream &os, const ProveCredentialKoR &proof) {
    os << "(";
    os << proof.c;
    os << ", ";
    os << proof.s1;
    os << ", ";
    os << proof.s2;
    os << ", ";
    os << proof.s3;
    os << ")";
    return os;
}

// σRnd = (h'', s'')
struct ProveCredentialSigmaRnd {
    element_t h;  // h'' ∈ G1
    element_t s;  // s'' ∈ G1
    std::string debug_info;
};

// ProveCredential çıktısı: (σRnd, k, πᵥ)
struct ProveCredentialOutput {
    ProveCredentialSigmaRnd sigmaRnd;  // (h'', s'')
    element_t k;                       // k = α₂ · (β₂)^(DID) · g₂^(r₂)
    ProveCredentialKoR proof_v;        // πᵥ = (c, s1, s2, s3)
};

ProveCredentialOutput proveCredential(
    TIACParams &params,
    AggregateSignature &aggSig,
    MasterVerKey &mvk,
    const std::string &didStr,
    const element_t o  // Blinding değeri; varsa kullanılacak
);

#endif
