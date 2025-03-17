#ifndef PREPAREBLINDSIGN_H
#define PREPAREBLINDSIGN_H

#include "setup.h"
#include <string>
#include <vector>

struct KoRProof {
    element_t c;
    element_t s1;
    element_t s2;
    element_t s3;
};

struct KoRProofDebug {
    KoRProof proof;         
    std::string r1;         
    std::string r2;       
    std::string r3;        
    std::string comi_prime; 
    std::string com_prime;  
    std::string kor_c;      
    std::string kor_s1;     
    std::string kor_s2;     
    std::string kor_s3;     
};


struct PrepareBlindSignDebug {
    std::string oi;        
    std::string didInt;   
    std::string comi;      
    std::string h;        
    std::string com;       
    std::string kor_r1;
    std::string kor_r2;
    std::string kor_r3;
    std::string kor_comi_prime;
    std::string kor_com_prime;
    std::string kor_c;
    std::string kor_s1;
    std::string kor_s2;
    std::string kor_s3;
};

struct PrepareBlindSignOutput {
    element_t comi;
    element_t h;
    element_t com;
    KoRProof  pi_s;
    mpz_t o; 
    PrepareBlindSignDebug debug;
};

PrepareBlindSignOutput prepareBlindSign(
    TIACParams &params, 
    const std::string &didStr
);

#endif
