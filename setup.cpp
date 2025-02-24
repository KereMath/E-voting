#include "setup.h"
#include <iostream>
#include <stdexcept>
#include <fstream>

/*
  Örnekte PBC'nin Type A parametresi (pbc_param_init_a_gen) gösterilmiştir.
  Gerçekte, "Type 3 Pairing" için BN eğrisi gibi parametreler kullanılabilir.
*/

TIACParams setupParams() {
    TIACParams params;

    // prime_order (p) için mpz_init
    mpz_init(params.prime_order);

    // (Örnek) 256-bit güvenlik için pbc parametresi oluştur
    // pbc_param_init_a_gen(par, rbit, qbit) -> basit tip A örneği
    pbc_param_t par;
    pbc_param_init_a_gen(par, 256, 512);

    // Parametrelerden pairing oluştur
    pairing_init_pbc_param(params.pairing, par);

    // pairing->r değeri, grubun mertebesi p
    mpz_set(params.prime_order, params.pairing->r);

    // G1 ve G2 elemanlarını init edip rastgele seçiyoruz
    element_init_G1(params.g1, params.pairing);
    element_init_G1(params.h1, params.pairing);
    element_init_G2(params.g2, params.pairing);

    element_random(params.g1);
    element_random(params.h1);
    element_random(params.g2);

    // pbc_param temizliği
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
