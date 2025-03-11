// kor.h - Knowledge of Representation algorithm implementation
#ifndef KOR_H
#define KOR_H

#include "setup.h"          // For TIACParams
#include "prepareblindsign.h" // To use the existing KoRProof struct
#include <string>
#include <pbc/pbc.h>

/**
 * Knowledge of Representation Algorithm (Algorithm 16)
 * Creates a proof that prover knows representation of specific values
 * 
 * @param params System parameters
 * @param h The h value (typically aggSig.h)
 * @param k The k value: k = α₂ · (β₂)^(did) · g₂^(r)
 * @param com The commitment: com = g₁^o · h^DIDi
 * @param alpha2 Alpha2 from master verification key
 * @param beta2 Beta2 from master verification key
 * @param r Random exponent used in k computation
 * @param did_elem DID as an element in Zr
 * @param o_elem o value as an element in Zr
 * @return KoRProof containing the proof elements (c, s1, s2, s3)
 */
KoRProof createKoRProof(
    TIACParams &params,
    const element_t h,      // Typically aggSig.h
    const element_t k,      // k = α₂ · (β₂)^(did) · g₂^(r)
    const element_t com,    // com = g₁^o · h^DIDi
    const element_t alpha2, // From mvk
    const element_t beta2,  // From mvk
    const element_t r,      // Random exponent used in k
    const element_t did_elem, // DID as an element
    const element_t o_elem  // o as an element
);

#endif // KOR_H