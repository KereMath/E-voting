#ifndef VERIFY_CREDENTIAL_H
#define VERIFY_CREDENTIAL_H

#include "setup.h"
#include "provecredential.h"
#include "aggregate.h"
#include <string>

// verifyCredential:
//   Inputs:
//     - params: TIAC parameters (contains pairing, g1, g2, etc.)
//     - pOut: ProveCredentialOutput (contains σRnd = (h'', s''), k and proof_v)
//     - mvk: Master Verification Key (α₂, β₂, β₁)
//     - aggSig: AggregateSignature (the aggregate signature, whose s component is used as com)
//   Output:
//     Returns true if both the KoR (Knowledge of Representation) check (Algorithm 17) and the pairing check (Algorithm 18)
//     pass, otherwise returns false.
bool verifyCredential(TIACParams &params,
                      ProveCredentialOutput &pOut,
                      MasterVerKey &mvk,
                      AggregateSignature &aggSig);

#endif
