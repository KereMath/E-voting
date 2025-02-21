#ifndef KEYGEN_H
#define KEYGEN_H

#include <vector>
#include "setup.h"

// Structure for each Election Authority's (EA) key pair
struct EAKey {
    element_t sgk1; // Signing key share 1: ∑_{l∈Q} Fl(i) in Zr
    element_t sgk2; // Signing key share 2: ∑_{l∈Q} Gl(i) in Zr
    element_t vkm1; // Verification key component 1: g2^sgk1 in G2
    element_t vkm2; // Verification key component 2: g2^sgk2 in G2
    element_t vkm3; // Verification key component 3: g1^sgk2 in G1
};

// Structure for the master verification key (mvk)
struct MasterVK {
    element_t alpha2; // g2^(∑ xi0) in G2
    element_t beta2;  // g2^(∑ yi0) in G2
    element_t beta1;  // g1^(∑ yi0) in G1
};

// Output structure for key generation
struct KeyGenOutput {
    MasterVK mvk;              // Master verification key
    std::vector<EAKey> eaKeys; // Vector of EA key pairs
};

// Function to perform Coconut TTP-less key generation
KeyGenOutput keygen(TIACParams params, int t, int ne);

// Function to clean up KeyGenOutput memory
void clearKeyGenOutput(KeyGenOutput& output);

#endif