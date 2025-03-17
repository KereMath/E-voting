#ifndef BLINDSIGN_H
#define BLINDSIGN_H

#include "setup.h"
#include "prepareblindsign.h" 
#include "keygen.h"        
#include <vector>
#include <string>

std::string elemToStrG1(element_t elem);

bool CheckKoR(
    TIACParams &params,
    element_t com,
    element_t comi,
    element_t h,
    KoRProof &pi_s
);

struct BlindSignature {
    element_t h;   
    element_t cm;  
    struct {
        int adminId;             
        int voterId;               
        std::string checkKoR_result;
        std::string computed_hash_comi; 
        std::string hx;           
        std::string comy;          
        std::string computed_cm;   
    } debug;
};

BlindSignature blindSign(
    TIACParams &params,
    PrepareBlindSignOutput &bsOut,
    mpz_t xm,
    mpz_t ym,
    int adminId,
    int voterId
);

#endif
