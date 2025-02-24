#include "setup.h"
#include <iostream>
#include <stdexcept>
#include <fstream>

/*
  Burada PBC'nin örnek "Type A" parametresi kullanılıyor (pbc_param_init_a_gen).
  Gerçek bir projede "Type 3 Pairing" için BN eğrisi gibi parametreler 
  veya kütüphanenin özel fonksiyonları kullanılabilir.
*/

TIACParams setupParams() {
    TIACParams params;

    // Asal mertebe p
    mpz_init(params.prime_order);

    // 256-bit güvenlik için örnek parametre oluştur
    pbc_param_t par;
    pbc_param_init_a_gen(par, 256, 512);

    // Parametrelerden pairing elde et
    pairing_init_pbc_param(params.pairing, par);

    // pairing->r grubun mertebesidir
    mpz_set(params.prime_order, params.pairing->r);

    // Elemanları init
    element_init_G1(params.g1, params.pairing);
    element_init_G1(params.h1, params.pairing);
    element_init_G2(params.g2, params.pairing);

    // Rastgele üreteçler
    element_random(params.g1);
    element_random(params.h1);
    element_random(params.g2);

    pbc_param_clear(par);

    return params;
}

void clearParams(TIACParams &params) {
    element_clear(params.g1);
    element_clear(params.h1);
    element_clear(params.g2);
    mpz_clear(params.prime_order);
    pairing_clear(params.pairing);
}
