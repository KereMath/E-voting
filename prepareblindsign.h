#ifndef PREPAREBLINDSIGN_H
#define PREPAREBLINDSIGN_H

#include "setup.h"
#include <string>
#include <vector>

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
   KoRProof için debug detayları
*/
struct KoRProofDebug {
    KoRProof proof;         // Asıl sonuç
    std::string r1;         // r1 değeri
    std::string r2;         // r2 değeri
    std::string r3;         // r3 değeri
    std::string comi_prime; // Hesaplanan comi′ (g1^r1 · h1^r2)
    std::string com_prime;  // Hesaplanan com′ (g1^r3 · h^r2)
    std::string kor_c;      // Hash sonucu c'nin string gösterimi
    std::string kor_s1;     // s1 değeri
    std::string kor_s2;     // s2 değeri
    std::string kor_s3;     // s3 değeri
};

/* 
  PrepareBlindSignDebug: Tüm ara değerlerin string gösterimlerini saklar
*/
struct PrepareBlindSignDebug {
    std::string oi;         // Seçilen oi değeri
    std::string didInt;     // did'in mpz_t karşılığı
    std::string comi;       // Hesaplanan comi
    std::string h;          // Hash sonucu h
    std::string com;        // Hesaplanan com
    // KoR ile ilgili debug bilgileri:
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

/* 
  PrepareBlindSignOutput (Algoritma 4 çıktısı):
    - comi (G1)
    - h (G1)
    - com (G1)
    - pi_s (KoRProof)
    - o (mpz_t)
    - debug (PrepareBlindSignDebug) -> Ara değerlerin detaylı gösterimi
*/
struct PrepareBlindSignOutput {
    element_t comi;
    element_t h;
    element_t com;
    KoRProof  pi_s;
    mpz_t o;  // prepareBlindSign() içinde hesaplanıp saklanmalı.
    PrepareBlindSignDebug debug;
};

/*
  prepareBlindSign (Algoritma 4):
   Girdi: 
     - params (TIACParams &)
     - didStr (string, DID hex)
   Çıktı: 
     - (comi, h, com, πs, debug)
*/
PrepareBlindSignOutput prepareBlindSign(
    TIACParams &params, 
    const std::string &didStr
);

#endif
