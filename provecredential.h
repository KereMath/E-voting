#ifndef PROVE_CREDENTIAL_H
#define PROVE_CREDENTIAL_H

#include "aggregate.h"  
#include "setup.h"       
#include <string>
#include <pbc/pbc.h>
#include <gmp.h>

struct ProveCredentialSigmaRnd {
    element_t h; 
    element_t s; 
    std::string debug_info;
};

struct ProveCredentialOutput {
    ProveCredentialSigmaRnd sigmaRnd;
    element_t k;                      
    element_t r;                     
    element_t c;
    element_t s1;
    element_t s2;
    element_t s3;
    std::string proof_v;             
};

ProveCredentialOutput proveCredential(
    TIACParams &params,
    AggregateSignature &aggSig,
    MasterVerKey &mvk,
    const std::string &didStr,
    const mpz_t o   
);

#endif