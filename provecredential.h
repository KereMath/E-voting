#ifndef PROVECREDENTIAL_H
#define PROVECREDENTIAL_H

#include "setup.h"
#include "keygen.h"   // MasterVerKey tanımlı (örneğin: mvk.alpha2, mvk.beta2, mvk.beta1)
#include "aggregate.h" // AggregateSignature tanımı
#include <string>

/*
  ProveCredentialOutput:
    - sigmaRnd: Randomized aggregate imza, σRnd = (h'', s'')
    - k: Hesaplanan k değeri
    - proof_v: KoR proof (π_v) – burada k’nin SHA512 hash’i kullanılıyor
*/
struct ProveCredentialOutput {
    AggregateSignature sigmaRnd;
    element_t k;
    std::string proof_v;
};

ProveCredentialOutput proveCredential(
    TIACParams &params,
    AggregateSignature &aggSig,
    MasterVerKey &mvk,
    const std::string &didStr
);

#endif
