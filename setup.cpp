#include "setup.h"
#include <cstring>
#include <string>
#include <fstream>
#include <iostream>

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
    pairing_init_pbc_param(params.pairing, pbcParams);

    // Grup mertebesini set et
    mpz_init_set(params.prime_order, params.pairing->r);

    // G1 ve G2 elemanlarını başlat
    element_init_G1(params.g1, params.pairing);
    element_init_G1(params.h1, params.pairing);
    element_init_G2(params.g2, params.pairing);

    // params.txt'den üreteçleri oku
    std::ifstream file("params.txt");
    if (!file.is_open()) {
        std::cerr << "params.txt dosyasi acilamadi!" << std::endl;
        return params;
    }

    std::string line;
    mpz_t temp;
    mpz_init(temp);

    // p (Grup mertebesi)
    std::getline(file, line); // "p (Grup mertebesi) ="
    std::getline(file, line);
    mpz_set_str(temp, line.c_str(), 10);
    if (mpz_cmp(temp, params.pairing->r) != 0) {
        std::cerr << "params.txt'deki p ile pairing->r eslesmiyor!" << std::endl;
    }

    // g1
    std::getline(file, line); // "g1 (G1 uretec) ="
    std::getline(file, line);
    std::string g1_str = line.substr(1, line.size() - 2); // Köşeli parantezleri kaldır
    size_t comma = g1_str.find(",");
    std::string g1_x = g1_str.substr(0, comma);
    std::string g1_y = g1_str.substr(comma + 1);
    element_t g1_x_elem, g1_y_elem;
    element_init_Zr(g1_x_elem, params.pairing);
    element_init_Zr(g1_y_elem, params.pairing);
    mpz_set_str(temp, g1_x.c_str(), 10);
    element_set_mpz(g1_x_elem, temp);
    mpz_set_str(temp, g1_y.c_str(), 10);
    element_set_mpz(g1_y_elem, temp);
    element_set1(params.g1); // Önce bir birim eleman set et
    element_set_mpz(params.g1, temp); // Sonra koordinatları manuel set et (PBC'nin bir bug'ı olabilir)
    element_set_si(params.g1->x, mpz_get_si(g1_x_elem->data)); // Doğrudan koordinat set etme
    element_set_si(params.g1->y, mpz_get_si(g1_y_elem->data));
    element_clear(g1_x_elem);
    element_clear(g1_y_elem);

    // h1
    std::getline(file, line); // "h1 (G1 ikinci uretec) ="
    std::getline(file, line);
    std::string h1_str = line.substr(1, line.size() - 2);
    comma = h1_str.find(",");
    std::string h1_x = h1_str.substr(0, comma);
    std::string h1_y = h1_str.substr(comma + 1);
    element_t h1_x_elem, h1_y_elem;
    element_init_Zr(h1_x_elem, params.pairing);
    element_init_Zr(h1_y_elem, params.pairing);
    mpz_set_str(temp, h1_x.c_str(), 10);
    element_set_mpz(h1_x_elem, temp);
    mpz_set_str(temp, h1_y.c_str(), 10);
    element_set_mpz(h1_y_elem, temp);
    element_set1(params.h1);
    element_set_si(params.h1->x, mpz_get_si(h1_x_elem->data));
    element_set_si(params.h1->y, mpz_get_si(h1_y_elem->data));
    element_clear(h1_x_elem);
    element_clear(h1_y_elem);

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
    element_t g2_x0_elem, g2_x1_elem, g2_y0_elem, g2_y1_elem;
    element_init_Zr(g2_x0_elem, params.pairing);
    element_init_Zr(g2_x1_elem, params.pairing);
    element_init_Zr(g2_y0_elem, params.pairing);
    element_init_Zr(g2_y1_elem, params.pairing);
    mpz_set_str(temp, g2_x0.c_str(), 10);
    element_set_mpz(g2_x0_elem, temp);
    mpz_set_str(temp, g2_x1.c_str(), 10);
    element_set_mpz(g2_x1_elem, temp);
    mpz_set_str(temp, g2_y0.c_str(), 10);
    element_set_mpz(g2_y0_elem, temp);
    mpz_set_str(temp, g2_y1.c_str(), 10);
    element_set_mpz(g2_y1_elem, temp);
    element_set1(params.g2);
    element_set_si(params.g2->x[0], mpz_get_si(g2_x0_elem->data));
    element_set_si(params.g2->x[1], mpz_get_si(g2_x1_elem->data));
    element_set_si(params.g2->y[0], mpz_get_si(g2_y0_elem->data));
    element_set_si(params.g2->y[1], mpz_get_si(g2_y1_elem->data));
    element_clear(g2_x0_elem);
    element_clear(g2_x1_elem);
    element_clear(g2_y0_elem);
    element_clear(g2_y1_elem);

    mpz_clear(temp);
    file.close();
    pbc_param_clear(pbcParams);

    // Pairing testi
    element_t gt;
    element_init_GT(gt, params.pairing);
    pairing_apply(gt, params.g1, params.g2, params.pairing);
    element_printf("Setup - e(g1, g2) = %B\n", gt);
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