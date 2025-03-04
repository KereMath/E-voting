#ifndef VERIFY_CREDENTIAL_H
#define VERIFY_CREDENTIAL_H

#include "setup.h"
#include "provecredential.h"  // For ProveCredentialOutput
#include <string>

bool verifyCredential(
    TIACParams &params,
    ProveCredentialOutput &pOut
);

#endif
