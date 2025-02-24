#ifndef PREPAREBLINDSIGN_H
#define PREPAREBLINDSIGN_H

#include "setup.h"
#include <string>

/* 
  KoRProof (πs): 
    c, s1, s2, s3 ∈ Zr
*/
struct KoRProof {
    element_t c;
    element_t s1;
    element_t s2;
    element_t s3;
};

/* 
  PrepareBlindSignOutput (Algoritma 4 çıktısı):
    - comi (G1)
    - h (G1)
    - com (G1)
    - pi_s (KoRProof)
*/
struct PrepareBlindSignOutput {
    element_t comi;
    element_t h;
    element_t com;
    KoRProof  pi_s;
};

/*
  prepareBlindSign (Algoritma 4):
   Girdi: 
     - params (TIACParams &)
     - didStr (string, DID hex)
   Çıktı: 
     - (comi, h, com, pi_s)
*/
PrepareBlindSignOutput prepareBlindSign(
    TIACParams &params, 
    const std::string &didStr
);

#endif
