#ifndef KOR_H
#define KOR_H

#include "setup.h"
#include <string>
#include <pbc/pbc.h>

// Using a different struct name to avoid conflicts
struct KnowledgeOfRepProof {
    element_t c;   // Challenge value
    element_t s1;  // First response value
    element_t s2;  // Second response value
    element_t s3;  // Third response value
    std::string proof_string; // String representation of the proof
};

/**
 * Knowledge of Representation Algorithm (Algorithm 16)
 * Creates a proof of knowledge of the representation of k and com
 * 
 * @param params System parameters containing pairing, g1, g2, etc.
 * @param h The h value (from aggregateResults[i].h)
 * @param k The k value computed as k = α₂ · (β₂)^(didInt) · g₂^r
 * @param com The commitment value (element_t)
 * @param alpha2 Alpha2 from master verification key
 * @param beta2 Beta2 from master verification key
 * @param r Random exponent used in k computation
 * @param did_int DID as an mpz_t integer
 * @param o The o value (from preparedOutputs[i].o)
 * @return KnowledgeOfRepProof containing the proof elements (c, s1, s2, s3)
 */
KnowledgeOfRepProof generateKoRProof(
    TIACParams &params,
    const element_t h,      // Typically from aggregateResults[i].h
    const element_t k,      // k = α₂ · (β₂)^(did) · g₂^r
    const element_t com,    // From converted preparedOutputs[i].debug.com
    const element_t alpha2, // From master verification key
    const element_t beta2,  // From master verification key
    const element_t r,      // Random exponent used in k
    const mpz_t did_int,    // DID as integer
    const mpz_t o           // From preparedOutputs[i].o
);

// Helper function to convert a string representation of an element to element_t
void stringToElement(element_t result, const std::string &str, pairing_t pairing, int element_type);

#endif // KOR_H