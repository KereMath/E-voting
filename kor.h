#ifndef KOR_H
#define KOR_H

#include "setup.h"
#include "prepareblindsign.h"  // This already has KoRProof definition
#include <string>
#include <pbc/pbc.h>

/**
 * Knowledge of Representation Algorithm (Algorithm 16)
 * Creates a proof of knowledge of the representation of k and com
 * 
 * @param params System parameters containing pairing, g1, g2, etc.
 * @param h The h value (from aggregateResults[i].h)
 * @param k The k value computed as k = α₂ · (β₂)^(didInt) · g₂^r
 * @param com The commitment value (from preparedOutputs[i].debug.com)
 * @param alpha2 Alpha2 from master verification key
 * @param beta2 Beta2 from master verification key
 * @param r Random exponent used in k computation
 * @param did_int DID as an mpz_t integer
 * @param o The o value (from preparedOutputs[i].o)
 * @return KoRProof containing the proof elements (c, s1, s2, s3)
 */
KoRProof createKoRProof(
    TIACParams &params,
    const element_t h,      // Typically from aggregateResults[i].h
    const element_t k,      // k = α₂ · (β₂)^(did) · g₂^r
    const element_t com,    // From preparedOutputs[i].debug.com
    const element_t alpha2, // From master verification key
    const element_t beta2,  // From master verification key
    const element_t r,      // Random exponent used in k
    const mpz_t did_int,    // DID as integer
    const mpz_t o           // From preparedOutputs[i].o
);

#endif // KOR_H