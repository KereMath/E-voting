#include "setup.h"
#include <iostream>
#include <cstring> // strlen vs. için

// Örnek BN-256 (type f) parametresi.
// Gerçek kullanımda güvenilir parametrelerinizi yerleştirmeniz önerilir.
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

    // 1. PBC parametresini yükle
    pbc_param_t pbcParams;
    pbc_param_init_set_buf(pbcParams, BN256_PARAM, std::strlen(BN256_PARAM));

    // 2. Pairing yapısını başlat
    pairing_init_pbc_param(params.pairing, pbcParams);

    // 3. G1, G2 gruplarının mertebesi (p)
    mpz_init_set(params.prime_order, params.pairing->r);

    // 4. Elemanların bellek/init ayarı
    element_init_G1(params.g1, params.pairing);
    element_init_G1(params.h1, params.pairing);
    element_init_G2(params.g2, params.pairing);

    // 5. Rastgele üreteç değerleri seç
    element_random(params.g1);
    element_random(params.h1);
    element_random(params.g2);

    // 6. Pairing tipini (symmetric/asymmetric) kontrol
    if (pairing_is_symmetric(params.pairing)) {
        std::cerr << "[Uyari] Seçilen pairing symmetric. Tip-3 (asymmetric) isteniyorsa parametrenizi kontrol edin.\n";
    }

    // 7. e(g1, g2) = 1 olmamasını sağlamak için gerekirse tekrar rastgele seç
    element_t tempGT;
    element_init_GT(tempGT, params.pairing);
    pairing_apply(tempGT, params.g1, params.g2, params.pairing);
    int attemptCount = 0;
    const int MAX_ATTEMPTS = 32;
    while (element_is1(tempGT) && attemptCount < MAX_ATTEMPTS) {
        element_random(params.g1);
        element_random(params.g2);
        pairing_apply(tempGT, params.g1, params.g2, params.pairing);
        attemptCount++;
    }
    element_clear(tempGT);
    
    if (attemptCount >= MAX_ATTEMPTS) {
        std::cerr << "[HATA] g1 ve g2 kimlik olmayan eleman bulunamadı! Parametrenizi tekrar gözden geçirin.\n";
    }

    // Artık pbc_param_t'yi temizleyebiliriz
    pbc_param_clear(pbcParams);

    return params;
}

void clearParams(TIACParams &params) {
    element_clear(params.g1);
    element_clear(params.h1);
    element_clear(params.g2);
    mpz_clear(params.prime_order);
    pairing_clear(params.pairing);
}
