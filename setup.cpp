#include "setup.h"
#include <stdexcept>
#include <string>

// Örnek BN256 parametre stringi. 
static const char* BN256_PARAM = R"(
type f
q 205523667896953300194896352429254920972540065223
r 205523667896953300194896352429254920972540065223
b 1
beta 115660053124364240149057221100520178164405286230
alpha0 191079354656274778837764015557338301375963168470
alpha1 71445317903696340296199556072836940741717506375
)";

TIACParams setupParams() {
    TIACParams params;

    // PBC parametrelerini oluşturuyoruz.
    pbc_param_t pbcParams;
    pbc_param_init_set_buf(pbcParams, BN256_PARAM, std::strlen(BN256_PARAM));

    // Pairing'i başlatıyoruz.
    pairing_init_pbc_param(params.pairing, pbcParams);
    pbc_param_clear(pbcParams);

    // G1, G2 ve GT üzerindeki elemanlar için yer ayırıyoruz.
    element_init_G1(params.g1, params.pairing);
    element_init_G1(params.h1, params.pairing);
    element_init_G2(params.g2, params.pairing);
    element_init_GT(params.gT, params.pairing);

    // Test amacıyla rastgele üreteçler kullanıyoruz.
    element_random(params.g1);
    element_random(params.h1);
    element_random(params.g2);

    // GT üreteci, pairing(g1, g2) ile hesaplanır.
    element_pairing(params.gT, params.g1, params.g2);

    // Grup mertebesi olarak pairing yapısındaki r değerini kullanıyoruz.
    mpz_init_set(params.prime_order, params.pairing->r);

    return params;
}

void clearParams(TIACParams &params) {
    element_clear(params.g1);
    element_clear(params.h1);
    element_clear(params.g2);
    element_clear(params.gT);
    mpz_clear(params.prime_order);
    pairing_clear(params.pairing);
}

#include <cstdlib>
#include <cstddef>

// Basit H: G1 → G1 hash fonksiyonu implementasyonu.
void hashG1(element_t out, element_t in) {
    int len = element_length_in_bytes(in);
    unsigned char* buffer = new unsigned char[len];
    element_to_bytes(buffer, in);
    element_from_hash(out, buffer, len);
    delete[] buffer;
}
