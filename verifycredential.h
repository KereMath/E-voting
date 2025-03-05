#ifndef VERIFY_CREDENTIAL_H
#define VERIFY_CREDENTIAL_H

#include "setup.h"
#include "provecredential.h"
#include "aggregate.h"
#include "keygen.h"
#include <string>

// verifyCredential: Verifies the credential proof by checking the KoR tuple and pairing equality.
// Input:
//    - params: System parameters
//    - pOut: ProveCredentialOutput structure (contains σRnd and k, and KoR tuple proof_v)
//    - mvk: Master verification key (contains α₂, β₂, etc.)
//    - aggSig: Aggregate signature (used for obtaining some parameters; e.g. its s may be needed)
//    - com: The commitment computed during the prepare phase (i.e., preparedOutputs[i].com)
// Output: true if verification passes; false otherwise.
bool verifyCredential(
    TIACParams &params,
    ProveCredentialOutput &pOut,
    MasterVerKey &mvk,
    AggregateSignature &aggSig,
    const element_t com
);

#endif
