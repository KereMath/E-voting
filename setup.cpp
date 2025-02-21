#include "setup.h"
#include <stdexcept>
#include <string>

// Örnek BN256 parametre stringi. (Güvenlik açısından üretim ortamında uygun parametreler kullanılmalıdır.)
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
    // pairing_t zaten pointer türüdür; pairing_init_pbc_param gerekli hafızayı ayırır.
    if (pairing_init_pbc_param(params.pairing, pbcParams) != 0) {
        pbc_param_clear(pbcParams);
        throw std::runtime_error("Pairing initialization failed.");
    }
    // pbcParams artık kullanılmadığından temizliyoruz.
    pbc_param_clear(pbcParams);

    // G1, G2 ve GT üzerindeki elemanlar için yer ayırıyoruz.
    element_init_G1(params.g1, params.pairing);
    element_init_G1(params.h1, params.pairing);
    element_init_G2(params.g2, params.pairing);
    element_init_GT(params.gT, params.pairing);

    // Üreteçleri rastgele seçmek yerine, sabit (deterministik) değerlerden türetiyoruz.
    // Bu sayede her çalıştırmada aynı üreteçler elde edilir.
    element_from_hash(params.g1, (const void*)"generator1", strlen("generator1"));
    element_from_hash(params.h1, (const void*)"generator2", strlen("generator2"));
    element_from_hash(params.g2, (const void*)"generator3", strlen("generator3"));

    // GT üreteci, pairing(g1, g2) ile hesaplanır.
    element_pairing(params.gT, params.g1, params.g2);

    // Grup mertebesini, G1'in gerçek order'ı ile hesaplıyoruz.
    mpz_init(params.prime_order);
    element_order(params.prime_order, params.g1);

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
// Burada, girdi elemanın byte gösterimini alıp element_from_hash ile başka bir G1 elemanına dönüştürüyoruz.
void hashG1(element_t out, const element_t in) {
    // 'in' elemanının bayt uzunluğunu al.
    int len = element_length_in_bytes(in);
    unsigned char* buffer = new unsigned char[len];
    element_to_bytes(buffer, in);

    // Byte dizisini G1 elemanına dönüştür.
    element_from_hash(out, buffer, len);

    delete[] buffer;
}
