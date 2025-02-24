#include "setup.h"
#include <cstring>
#include <iostream>

// Örnek BN-256 (type f) parametresi.
// Gerçek projede güvenilir bir kaynak veya param dosyası kullanmanız önerilir.
static const char* BN256_PARAM = R"(
type f
q 186944716490498228592211144210229761989241675946164825413929
r 186944716490498228592211144210229761989241675946164825526319
b 1
beta 109341043287096796981443118641762728007143963588
alpha0 147354120310549301445722100263386112552812769040
alpha1 12707752274141484575335849047546472705710528192
)";

TIACParams setupParams() {
    TIACParams params;

    // 1) PBC parametresini yükle
    pbc_param_t pbcParam;
    pbc_param_init_set_buf(pbcParam, BN256_PARAM, std::strlen(BN256_PARAM));

    // 2) Pairing yapısını başlat
    pairing_init_pbc_param(params.pairing, pbcParam);

    // 3) Grubun asal mertebesini p = r ile mpz_t'ye kopyala
    mpz_init_set(params.prime_order, params.pairing->r);

    // 4) G1 ve G2 elemanlarını init
    element_init_G1(params.g1, params.pairing);
    element_init_G1(params.h1, params.pairing);
    element_init_G2(params.g2, params.pairing);

    // 5) Rastgele üreteç değerleri seç
    element_random(params.g1);
    element_random(params.h1);
    element_random(params.g2);

    // 6) Pairing’in symmetric/asymmetric durumunu kontrol
    if (pairing_is_symmetric(params.pairing)) {
        std::cerr << "[Warning] Seçilen pairing symmetric. Tip-3 (asymmetric) istiyorsanız parametreyi değiştirin.\n";
    }

    // 7) e(g1, g2) != 1 olacak şekilde tekrar seçme
    element_t testGT;
    element_init_GT(testGT, params.pairing);
    pairing_apply(testGT, params.g1, params.g2, params.pairing);

    int attempts = 0, MAX_ATTEMPTS = 32;
    while(element_is1(testGT) && attempts < MAX_ATTEMPTS) {
        element_random(params.g1);
        element_random(params.g2);
        pairing_apply(testGT, params.g1, params.g2, params.pairing);
        attempts++;
    }
    element_clear(testGT);

    if (attempts >= MAX_ATTEMPTS) {
        std::cerr << "[ERROR] Uygun g1, g2 rastgele seçilemedi. Parametreyi gözden geçirin!\n";
    }

    // 8) pbc_param temizle
    pbc_param_clear(pbcParam);
    return params;
}

void clearParams(TIACParams &params) {
    element_clear(params.g1);
    element_clear(params.h1);
    element_clear(params.g2);
    mpz_clear(params.prime_order);
    pairing_clear(params.pairing);
}
