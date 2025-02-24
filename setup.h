#ifndef SETUP_H
#define SETUP_H

#include <pbc/pbc.h>
#include <gmp.h>

/**
 * Bilinear grup parametrelerini tutan yapı
 * (Tip-3 pairing: G1, G2, GT).
 */
struct TIACParams {
    pairing_t pairing;    // Pairing yapısı
    mpz_t prime_order;    // Asal mertebe p (== r)
    element_t g1;         // G1 üzerinde üreteç
    element_t h1;         // G1 üzerinde ikinci üreteç
    element_t g2;         // G2 üzerinde üreteç
};

/**
 * BN-256 parametresi yükler,
 * (g1, h1, g2) rastgele seçer,
 * e(g1, g2) != 1 kontrolü yapar.
 */
TIACParams setupParams();

/**
 * Parametreleri bellekten temizler.
 */
void clearParams(TIACParams &params);

#endif // SETUP_H
