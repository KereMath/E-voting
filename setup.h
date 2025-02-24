#ifndef SETUP_H
#define SETUP_H

#include <pbc/pbc.h>
#include <gmp.h>

// TIACParams yapısı, sistemde ihtiyacımız olan temel parametreleri tutar:
//  - pairing: PBC kütüphanesinin pairing (çift doğrusal eşleme) bilgisini tutar
//  - prime_order: Grupların asal mertebesi p
//  - g1, h1: G1 üzerindeki üreteçler
//  - g2: G2 üzerindeki üreteç
struct TIACParams {
    pairing_t pairing;
    mpz_t prime_order;
    element_t g1;
    element_t g2;
    element_t h1;
};

// Algoritma 1: TIAC Kurulum
// 1) λ-bit asal mertebeli bilinear group (G1, G2, GT, p)
// 2) G1’de g1, h1 ve G2’de g2 üreteçlerini rastgele seç
// 3) TIACParams içinde döndür
TIACParams setupParams();

// Bellek temizliği
void clearParams(TIACParams &params);

#endif
