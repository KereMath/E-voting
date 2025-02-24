#ifndef SETUP_H
#define SETUP_H

#include <pbc/pbc.h>
#include <gmp.h>

/**
 *  TIAC/Coconut sisteminde kullanılacak
 *  bilinear grup parametrelerini tutan yapı.
 */
struct TIACParams {
    pairing_t pairing;    // pairing yapısı (const olmamalı)
    mpz_t prime_order;    // Grubun asal mertebesi p
    element_t g1;         // G1 üzerindeki üreteç
    element_t h1;         // G1 üzerindeki ikinci üreteç
    element_t g2;         // G2 üzerindeki üreteç
};

// Kurulum fonksiyonu: BN-256 parametresi yüklenir, (g1, h1, g2) seçilir.
TIACParams setupParams();

// Parametreleri bellekten temizler.
void clearParams(TIACParams &params);

#endif // SETUP_H
