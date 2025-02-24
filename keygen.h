// keygen.h (örnek)
#ifndef KEYGEN_H
#define KEYGEN_H

#include "setup.h"

struct EAKey {
    element_t x0, y0;        // sabit terimler
    element_t sgk1, sgk2;    // local signing share
    element_t vki1, vki2, vki3; // local verify share
    element_t* Vx;          // commitments g2^(x_{ij})
    element_t* Vy;          // commitments g2^(y_{ij})
    element_t* Vyprime;     // commitments g1^(y_{ij})
};

struct MasterVK {
    element_t vk1; 
    element_t vk2;
    element_t vk3;
};

struct MasterSK {
    element_t sk1;
    element_t sk2;
};

struct KeyGenOutput {
    MasterVK mvk;
    MasterSK msgk;
    EAKey* eaKeys;   // dizi [n] boyutunda
};

KeyGenOutput keygen(TIACParams &params, int t, int n);

#endif
