#include "setup.h"
#include <cstring>  // strlen vb. için
#include <string>
#include <iostream>

// Örnek BN-256 (type f) parametresi.
// Gerçek kullanımda kendi güvenilir parametrenizi yerleştirin.
static const char* BN256_PARAM = R"(
type f
q 16798108731015832284940804142231733909759579603404752749028378864165570215949
r 16798108731015832284940804142231733909759579603404752749028378864165570215949
b 2
beta 1
alpha0 0
alpha1 1
)";

TIACParams setupParams() {
    TIACParams params;

    // PBC parametresini yükle
    pbc_param_t pbcParams;
    pbc_param_init_set_buf(pbcParams, BN256_PARAM, std::strlen(BN256_PARAM));

    // Pairing yapısını başlat
    pairing_init_pbc_param(params.pairing, pbcParams);

    // G1, G2 gruplarının mertebesi (p)
    mpz_init_set(params.prime_order, params.pairing->r);

    // G1 ve G2 üzerinde elementleri başlat
    element_init_G1(params.g1, params.pairing);
    element_init_G1(params.h1, params.pairing);
    element_init_G2(params.g2, params.pairing);

    // Rastgele üreteç değerleri seç
    element_random(params.g1);
    element_random(params.h1);
    element_random(params.g2);

    // Ek: Pairing tipini denetle
    if (pairing_is_symmetric(params.pairing)) {
        std::cerr << "[Uyari] Pairing symmetric olmus olabilir, BN-256 parametresi kontrol edin.\n";
    }

    // Ek: E(g1, g2) kontrolu
    element_t testGT;
    element_init_GT(testGT, params.pairing);
    pairing_apply(testGT, params.g1, params.g2, params.pairing);
    if (element_is1(testGT)) {
        std::cerr << "[Uyari] g1 veya g2 kimlik elemani, tekrar rastgele seciliyor.\n";
        int attemptCount = 0;
        const int MAX_ATTEMPTS = 100;
        do {
            element_random(params.g1);
            element_random(params.g2);
            pairing_apply(testGT, params.g1, params.g2, params.pairing);
            attemptCount++;
            if (attemptCount > MAX_ATTEMPTS) {
                std::cerr << "[Hata] " << MAX_ATTEMPTS << " defa denenmesine ragmen kimlik olmayan eleman bulunamadi.\n";
                break;
            }
        } while (element_is1(testGT));
    }
    element_clear(testGT);

    // Artık pbc_param_t'yi temizleyebiliriz
    pbc_param_clear(pbcParams);

    return params;
}

void clearParams(TIACParams &params) {
    // Elementleri, mpz_t değerini ve pairing yapısını temizle
    element_clear(params.g1);
    element_clear(params.h1);
    element_clear(params.g2);
    mpz_clear(params.prime_order);
    pairing_clear(params.pairing);
}
