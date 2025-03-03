#ifndef PREPAREBLINDSIGN_H
#define PREPAREBLINDSIGN_H

#include "setup.h"
#include <string>

/*
  KoRProof: c, s1, s2, s3 in Zr (not always strictly needed 
            but let's keep for completeness)
*/
struct KoRProof {
    element_t c;
    element_t s1;
    element_t s2;
    element_t s3;
};

/*
  PrepareBlindSignOutput:
   - comi (G1)
   - h    (G1)
   - com  (G1)
   - pi_s (KoRProof)
   - o    (mpz_t) random factor
*/
struct PrepareBlindSignOutput {
    element_t comi;
    element_t h;
    element_t com;
    KoRProof  pi_s;
    mpz_t      o; 
};

/*
  prepareBlindSign (Alg.4):
   1) pick random o, o_i
   2) comi = g1^o_i * h1^did
   3) h = HashInG1(comi)
   4) com = g1^o * h^did
   5) pi_s = ...
   ...
*/
PrepareBlindSignOutput prepareBlindSign(
    TIACParams &params, 
    const std::string &didStr
);

#endif
