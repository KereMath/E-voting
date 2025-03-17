#ifndef UNBLINDSIGN_H
#define UNBLINDSIGN_H

#include "setup.h"
#include "prepareblindsign.h"
#include "keygen.h"
#include "blindsign.h"
#include <string>

std::string elementToStringG1(element_t elem);

struct UnblindSignature {
    element_t h;   
    element_t s_m; 
    struct {
        std::string hash_comi;    
        std::string computed_s_m; 
        std::string pairing_lhs; 
        std::string pairing_rhs;
    } debug;
};


UnblindSignature unblindSign(
    TIACParams &params,
    PrepareBlindSignOutput &bsOut,
    BlindSignature &blindSig,
    EAKey &eaKey,
    const std::string &didStr
);

#endif
