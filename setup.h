#ifndef SETUP_H
#define SETUP_H

#include <pbc/pbc.h>
#include <gmp.h>

// TIAC/Coconut parametre yapısı
struct TIACParams {
    pairing_t pairing;   // G1, G2, GT gruplarını tanımlayan çiftleme
    mpz_t prime_order;   // Grup mertebesi (asal p)
    element_t g1;        // G1'in üreteci
    element_t h1;        // G1'de ikinci üreteç
    element_t g2;        // G2'nin üreteci
};

// Sistem parametrelerini oluşturan fonksiyon
TIACParams setupParams();

// Kaynakları temizleme fonksiyonu
void clearParams(TIACParams &params);

#endif