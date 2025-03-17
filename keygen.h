#ifndef KEYGEN_H
#define KEYGEN_H

#include "setup.h"
#include <vector>

struct MasterVerKey {
    element_t alpha2; 
    element_t beta2;  
    element_t beta1;  
};


struct EAKey {
    element_t sgk1;
    element_t sgk2;
    element_t vkm1;
    element_t vkm2;
    element_t vkm3;
};

struct KeyGenOutput {
    MasterVerKey mvk;
    std::vector<EAKey> eaKeys;
};

KeyGenOutput keygen(TIACParams &params, int t, int ne);

#endif
