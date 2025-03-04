#ifndef PROVE_CREDENTIAL_H
#define PROVE_CREDENTIAL_H

#include "setup.h"
#include "aggregate.h"
#include "keygen.h"
#include <string>

struct ProveCredentialSignature {
    element_t h; // h'' değeri
    element_t s; // s'' değeri
    std::string debug_info;
};

struct ProveCredentialOutput {
    ProveCredentialSignature sigmaRnd; // (h'', s'')
    element_t k;                       // k değeri
    std::string proof_v;               // π_v: k'nin SHA512 hash'ı
};

/**
 * @brief Seçmenin aggregate imzası üzerinde imza kanıtı (prove credential) üretir.
 * 
 * @param params TIAC parametreleri
 * @param aggSig Aggregate imza (AggregateSignature)
 * @param mvk Master Verification Key (mvk); burada mvk.alpha2 = g₂^x₂, mvk.beta2 = g₂^y₂, mvk.beta1 = g₁^y₁
 * @param didStr Seçmenin DID değeri (hex string)
 * @return ProveCredentialOutput
 */
ProveCredentialOutput proveCredential(TIACParams &params,
                                        AggregateSignature &aggSig,
                                        MasterVerKey &mvk,
                                        const std::string &didStr);

#endif // PROVE_CREDENTIAL_H
