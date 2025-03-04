#ifndef PROVE_CREDENTIAL_H
#define PROVE_CREDENTIAL_H

#include "aggregate.h"    // AggregateSignature, MasterVerKey
#include "setup.h"        // TIACParams
#include <string>

// Tuple şeklinde KoR ispatını saklamak için:
struct ProveCredentialKoR {
    std::string c;   // c: Hash sonucu (Zr elemanının string gösterimi)
    std::string s1;  // s1 = r1' − c·r1
    std::string s2;  // s2 = r2' − c·(DID)
    std::string s3;  // s3 = r3' − c·o   (Burada o = 0 kabul edilmiştir)
    std::string debug_info; // Tüm ara değerlerin detaylı dökümü
};

// Operator<< aşırı yüklemesi (yazdırmak için)
inline std::ostream& operator<<(std::ostream &os, const ProveCredentialKoR &proof) {
    os << "(" << proof.c << ", " << proof.s1 << ", " << proof.s2 << ", " << proof.s3 << ")";
    return os;
}

// σRnd = (h″, s″)
struct ProveCredentialSigmaRnd {
    element_t h;  // h″ ∈ G1
    element_t s;  // s″ ∈ G1
    std::string debug_info;
};

// ProveCredential çıktısı: (σRnd, k, πᵥ)
struct ProveCredentialOutput {
    ProveCredentialSigmaRnd sigmaRnd;  // (h″, s″)
    element_t k;                       // k = α₂ · (β₂)^(DID) · g₂^(r₂)
    ProveCredentialKoR proof_v;        // KoR ispatı tuple: (c, s1, s2, s3)
};

ProveCredentialOutput proveCredential(
    TIACParams &params,
    AggregateSignature &aggSig,
    MasterVerKey &mvk,
    const std::string &didStr,
    const element_t o   // seçmenin blinding aşamasında kullandığı o değeri (varsa; burada örneğin 0 olarak verilebilir)
);

#endif
