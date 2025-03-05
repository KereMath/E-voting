#ifndef VERIFY_CREDENTIAL_H
#define VERIFY_CREDENTIAL_H

#include "setup.h"
#include "provecredential.h"
#include "aggregate.h"
#include "keygen.h"
#include <string>

// verifyCredential: ProveCredential çıktısını (πᵥ, σRnd, k) alır, 
// Master Verification Key (mvk) ve Aggregate Signature (aggSig) ile birlikte, 
// ayrıca prepare aşamasında hesaplanan "com" değerini kullanarak,
// KoR tuple kontrolü ve pairing kontrolü yapar. 
// Döndürülen değer: true (doğrulama başarılı) veya false (başarısız).
bool verifyCredential(
    TIACParams &params,
    ProveCredentialOutput &pOut,
    MasterVerKey &mvk,
    AggregateSignature &aggSig,
    const element_t com  // com: prepare aşamasından gelen değer (örneğin, preparedOutputs[i].com)
);

#endif
