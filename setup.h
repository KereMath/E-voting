#ifndef SETUP_H
#define SETUP_H

#include <pbc/pbc.h>
#include <gmp.h>

// TIACParams: sistemin temel parametrelerini tutar
//  pairing     : PBC kütüphanesinin pairing (çift doğrusal eşleme) nesnesi
//  prime_order : Grupların asal mertebesi p
//  g1, h1      : G1 üzerindeki üreteçler
//  g2          : G2 üzerindeki üreteç
struct TIACParams {
    pairing_t pairing; 
    mpz_t prime_order;
    element_t g1;
    element_t g2;
    element_t h1;
};

// Algoritma 1: TIAC Kurulum (p, G1, G2, h1 üretimi)
TIACParams setupParams();

// Oluşturulan parametreleri bellekten temizler
void clearParams(TIACParams &params);

#endif
