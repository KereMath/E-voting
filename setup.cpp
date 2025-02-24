#include "setup.h"
#include <iostream>
#include <fstream>
#include <stdexcept>

/*
  Bu örnekte PBC kütüphanesinin Type A (BN veya başka bir eğri) 
  parametre oluşturma fonksiyonları kullanılmaktadır.
  Gerçek bir "Type 3 Pairing" (kütüphaneye göre Type E, F vs. olabilir) 
  parametreleri, pbc_param_init_*(...) fonksiyonuyla veya hazır param dosyasıyla
  ayarlanır. Burada basitlik adına pbc_param_init_a_gen ile örnek gösterilmiştir.
*/

TIACParams setupParams() {
    TIACParams params;

    // mpz_t gibi alanları init etmemiz gerekiyor
    mpz_init(params.prime_order);

    // 256 bit güvenlik için yaklaşık parametre
    // (Elbette gerçek projede "a_gen" yerine 
    //  BN tipi eğri parametreleri kullanılabilir.)
    pbc_param_t par;
    // 256 bitlik bir prime ve 512 bitlik alan parametresi
    pbc_param_init_a_gen(par, 256, 512);

    // pairing_init_pbc_param ile parametrelerden pairing oluşturuluyor
    pairing_init_pbc_param(params.pairing, par);

    // pairing->r, G1 (ve G2) gruplarının mertebesini (asar mertebe p) tutar
    mpz_set(params.prime_order, params.pairing->r);

    // G1, G2, h1 elementlerini init
    element_init_G1(params.g1, params.pairing);
    element_init_G1(params.h1, params.pairing);
    element_init_G2(params.g2, params.pairing);

    // Rastgele üreteç seçimi
    element_random(params.g1);
    element_random(params.h1);
    element_random(params.g2);

    // Artık par kullanılmayacağından temizleyelim
    pbc_param_clear(par);

    return params;
}

void clearParams(TIACParams &params) {
    element_clear(params.g1);
    element_clear(params.g2);
    element_clear(params.h1);
    mpz_clear(params.prime_order);
    pairing_clear(params.pairing);
}
