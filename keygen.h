#ifndef KEYGEN_H
#define KEYGEN_H

#include <vector>
#include "setup.h"

struct EAKey {
    element_t sgk1; // ∑_{l∈Q} Fl(i)
    element_t sgk2; // ∑_{l∈Q} Gl(i)
    element_t vkm1; // g2^sgk1
    element_t vkm2; // g2^sgk2
    element_t vkm3; // g1^sgk2
};

struct MasterVK {
    element_t alpha2; // g2^(∑ xi0)
    element_t beta2;  // g2^(∑ yi0)
    element_t beta1;  // g1^(∑ yi0)
};

struct KeyGenOutput {
    MasterVK mvk;
    std::vector<EAKey> eaKeys;
};

KeyGenOutput keygen(TIACParams params, int t, int ne);

#endif