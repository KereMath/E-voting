#ifndef CHECKKORVERIFY_H
#define CHECKKORVERIFY_H

#include "setup.h"
#include "provecredential.h"
#include <string>
#include <gmp.h>
#include <pbc/pbc.h>

/**
 * Checks if the Knowledge of Representation (KoR) proof is valid
 * 
 * @param params TIAC parameters for the cryptographic setup
 * @param proveOutput The output from the proveCredential phase containing the proof
 * @param mvk Master verification key
 * @param com The commitment value from the prepareBlindSign phase
 * @return bool True if the KoR verification passes, false otherwise
 */
bool checkKoRVerify(
    TIACParams &params,
    const ProveCredentialOutput &proveOutput,
    const MasterVerKey &mvk,
    const std::string &com
);

/**
 * Helper function to parse the KoR proof tuple from string
 * 
 * @param proof_v The string representation of the proof tuple (c, s1, s2, s3)
 * @param c Output parameter for the challenge value
 * @param s1 Output parameter for the first response
 * @param s2 Output parameter for the second response
 * @param s3 Output parameter for the third response
 * @param pairing The pairing context for element initialization
 * @return bool True if parsing was successful, false otherwise
 */
bool parseKoRProof(
    const std::string &proof_v,
    element_t c,
    element_t s1,
    element_t s2,
    element_t s3,
    pairing_t pairing
);

#endif // CHECKKORVERIFY_H