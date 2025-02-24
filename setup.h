#ifndef SETUP_H
#define SETUP_H

#include <pbc/pbc.h>
#include <gmp.h>

/**
 * TIAC/Coconut benzeri sistemlerde kullanılacak
 * bilinear grup parametrelerini tutan yapı.
 */
struct TIACParams {
    pairing_t pairing;   // Pairing yapısı (non-const)
    mpz_t prime_order;   // Grubun asal mertebesi p
    element_t g1;        // G1 üzerindeki üreteç
    element_t h1;        // G1 üzerindeki ikinci üreteç
    element_t g2;        // G2 üzerindeki üreteç
};

/**
 * BN-256 parametresiyle tip-3 bilinear grup kurar,
 * (g1, h1, g2) rastgele seçer ve e(g1, g2) != 1 kontrolü yapar.
 */
TIACParams setupParams();

/**
 * Parametreleri bellekten temizler.
 */
void clearParams(TIACParams &params);

#endif // SETUP_H
