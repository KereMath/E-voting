#ifndef SETUP_H
#define SETUP_H

#include <pbc/pbc.h>
#include <gmp.h>

// TIAC/Coconut sistem parametrelerini tutan yapı
struct TIACParams {
    pairing_t pairing;    // PBC pairing objesi
    mpz_t prime_order;    // Grubun asal mertebesi (p)
    element_t g1;         // G1 üzerinde üreteç
    element_t h1;         // G1 üzerinde ikinci üreteç
    element_t g2;         // G2 üzerinde üreteç
};

// Kurulum fonksiyonumuz: BN-256 parametresi kullanarak G1, G2 üreteçlerini ve mertebe p'yi oluşturur.
TIACParams setupParams();

// Oluşturulmuş parametreleri (bellek yönetimi açısından) temizleyen fonksiyon.
void clearParams(TIACParams &params);

#endif // SETUP_H
