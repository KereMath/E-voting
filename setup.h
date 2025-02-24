#ifndef SETUP_H
#define SETUP_H

#include <pbc/pbc.h>
#include <gmp.h>

// TIACParams yapısı, sistemde ihtiyacımız olan temel parametreleri tutar.
// pairing: PBC kütüphanesinin pairing bilgisini tutar
// prime_order: Grupların asal mertebesi p (örn. 256-bit)
// g1, g2: Sırasıyla G1 ve G2 üzerinde oluşturulan üreteçler
// h1: G1 üzerinde ek bir üreteç (coconut şeması için)
struct TIACParams {
    pairing_t pairing;
    mpz_t prime_order;
    element_t g1;
    element_t g2;
    element_t h1;
};

// Sistemi kurup TIACParams döndüren fonksiyon.
// Bu fonksiyon, Algoritma 1’deki adımları gerçekleştirir:
//  1) λ-bit asal mertebeli bilinear group seç (p, G1, G2, GT)
//  2) G1 içinde g1, h1 ve G2 içinde g2 üreteçlerini seç
//  3) Hepsini TIACParams içinde döndür
TIACParams setupParams();

// Oluşturulan parametreleri bellekte temizlemek için
void clearParams(TIACParams &params);

#endif
