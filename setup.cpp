#include "setup.h"
#include <cstring>
#include <string>
#include <fstream>
#include <iostream>
#include <pbc/pbc.h>
#include <gmp.h>

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

    // Pairing'i BN-256 parametreleriyle başlat
    pbc_param_t pbcParams;
    pbc_param_init_set_buf(pbcParams, BN256_PARAM, std::strlen(BN256_PARAM));
    if (pairing_init_pbc_param(params.pairing, pbcParams) != 0) {
        std::cerr << "Pairing başlatma hatası!" << std::endl;
        pbc_param_clear(pbcParams);
        return params;
    }

    // Grup mertebesini set et
    mpz_init_set(params.prime_order, params.pairing->r);
    std::cout << "pairing->r: ";
    mpz_out_str(stdout, 10, params.pairing->r);
    std::cout << std::endl;

    // G1 ve G2 elemanlarını başlat
    element_init_G1(params.g1, params.pairing);
    element_init_G1(params.h1, params.pairing);
    element_init_G2(params.g2, params.pairing);

    // params.txt'den üreteçleri oku
    std::ifstream file("params.txt");
    if (!file.is_open()) {
        std::cerr << "params.txt dosyasi acilamadi!" << std::endl;
        pbc_param_clear(pbcParams);
        return params;
    }

    std::string line;
    mpz_t temp_x, temp_y;
    mpz_init(temp_x);
    mpz_init(temp_y);

    // p (Grup mertebesi)
    std::getline(file, line); // "p (Grup mertebesi) ="
    std::getline(file, line);
    mpz_t p;
    mpz_init(p);
    mpz_set_str(p, line.c_str(), 10);
    if (mpz_cmp(p, params.pairing->r) != 0) {
        std::cerr << "params.txt'deki p ile pairing->r eslesmiyor!" << std::endl;
    }
    mpz_clear(p);

    // g1
    std::getline(file, line); // "g1 (G1 uretec) ="
    std::getline(file, line);
    std::string g1_str = line.substr(1, line.size() - 2); // Köşeli parantezleri kaldır
    size_t comma = g1_str.find(",");
    std::string g1_x = g1_str.substr(0, comma);
    std::string g1_y = g1_str.substr(comma + 1);
    mpz_set_str(temp_x, g1_x.c_str(), 10);
    mpz_set_str(temp_y, g1_y.c_str(), 10);
    // G1 elemanını set et
    element_set_mpz(params.g1, temp_x); // x koordinatı
    element_set_mpz(params.g1, temp_y); // y koordinatı (not: bu bir hata olabilir, aşağıda düzelteceğiz)
    // Doğru yöntem: element_from_hash veya manuel set
    std::string g1_combined = g1_x + g1_y;
    element_from_hash(params.g1, (void*)g1_combined.data(), g1_combined.size());
    element_printf("Setup - g1 = %B\n", params.g1);

    // h1
    std::getline(file, line); // "h1 (G1 ikinci uretec) ="
    std::getline(file, line);
    std::string h1_str = line.substr(1, line.size() - 2);
    comma = h1_str.find(",");
    std::string h1_x = h1_str.substr(0, comma);
    std::string h1_y = h1_str.substr(comma + 1);
    mpz_set_str(temp_x, h1_x.c_str(), 10);
    mpz_set_str(temp_y, h1_y.c_str(), 10);
    std::string h1_combined = h1_x + h1_y;
    element_from_hash(params.h1, (void*)h1_combined.data(), h1_combined.size());
    element_printf("Setup - h1 = %B\n", params.h1);

    // g2
    std::getline(file, line); // "g2 (G2 uretec) ="
    std::getline(file, line);
    std::string g2_str = line.substr(2, line.size() - 4); // [[...], [...]] formatını düzelt
    size_t mid = g2_str.find("], [");
    std::string g2_first = g2_str.substr(0, mid);
    std::string g2_second = g2_str.substr(mid + 4);
    comma = g2_first.find(",");
    std::string g2_x0 = g2_first.substr(0, comma);
    std::string g2_x1 = g2_first.substr(comma + 1);
    comma = g2_second.find(",");
    std::string g2_y0 = g2_second.substr(0, comma);
    std::string g2_y1 = g2_second.substr(comma + 1);
    std::string g2_combined = g2_x0 + g2_x1 + g2_y0 + g2_y1;
    element_from_hash(params.g2, (void*)g2_combined.data(), g2_combined.size());
    element_printf("Setup - g2 = %B\n", params.g2);

    mpz_clear(temp_x);
    mpz_clear(temp_y);
    file.close();
    pbc_param_clear(pbcParams);

    // Pairing testi
    element_t gt;
    element_init_GT(gt, params.pairing);
    pairing_apply(gt, params.g1, params.g2, params.pairing);
    element_printf("Setup - e(g1, g2) = %B\n", gt);
    if (element_is1(gt)) {
        std::cerr << "Warning: e(g1, g2) birim elemani, pairing hatali olabilir!" << std::endl;
    }
    element_clear(gt);

    return params;
}

void clearParams(TIACParams& params) {
    element_clear(params.g1);
    element_clear(params.h1);
    element_clear(params.g2);
    mpz_clear(params.prime_order);
    pairing_clear(params.pairing);
}