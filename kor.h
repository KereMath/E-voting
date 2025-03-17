#ifndef KOR_H
#define KOR_H

#include "setup.h"
#include <string>
#include <pbc/pbc.h>

struct KnowledgeOfRepProof {
    element_t c;   
    element_t s1;  
    element_t s2;  
    element_t s3; 
    std::string proof_string; 
};

KnowledgeOfRepProof generateKoRProof(
    TIACParams &params,
    const element_t h,     
    const element_t k,     
    const element_t r,     
    const element_t com,    
    const element_t alpha2, 
    const element_t beta2, 
    const mpz_t did_int,    
    const mpz_t o          
);

void stringToElement(element_t result, const std::string &str, pairing_t pairing, int element_type);

#endif // KOR_H