#ifndef SETUP_H
#define SETUP_H

#include <pbc/pbc.h>
#include <gmp.h>
#include <cstring>

// TIAC/Coconut parametrelerini tutacak yapı.
// pairing_t tipi, PBC kütüphanesinde pointer türüdür ve pairing_init_* fonksiyonları
// bu pointer üzerinden gerekli hafıza ayırmasını yapar.
struct TIACParams {
    pairing_t pairing;   // PBC pairing objesi
    mpz_t prime_order;   // G1 grubunun gerçek mertebesi (p)
    element_t g1;        // G1 için sabit üreteç (deterministik olarak türetilmiş)
    element_t h1;        // G1 için ikinci sabit üreteç (örneğin hash fonksiyonu için kullanılabilir)
    element_t g2;        // G2 için sabit üreteç
    element_t gT;        // GT için üreteç (pairing(g1, g2) ile elde edilir)
};

// BN256 (örnek) parametreleri kullanılarak TIAC parametrelerini başlatır.
// Not: Gerçek uygulamada daha güvenilir ve güncel parametreler tercih edilmelidir.
TIACParams setupParams();

// Oluşturulan parametrelerde kullanılan tüm kaynakları temizler.
void clearParams(TIACParams &params);

// Hash fonksiyonu H: G1 → G1. Verilen G1 elemanını sabit bir hash algoritması ile başka bir G1 elemanına dönüştürür.
void hashG1(element_t out, const element_t in);

#endif // SETUP_H
