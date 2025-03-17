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
    int adminId;   // Moved from debug struct
    int voterId;   // Moved from debug struct
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