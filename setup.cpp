#include "setup.h"
#include <stdexcept>
#include <string>

static const char* BN256_PARAM = R"(
type d
q 25195908475657893494027183240048397689940557347513054227947345557770262917187
h 1
r 25195908475657893494027183240048397689940557347513054227947345557770262917187
n 25195908475657893494027183240048397689940557347513054227947345557770262917187
a 0
b 3
k 6
hk 25062608225816371759792539131299361753640647431616701360871338285845816347766
nqr 5
coeff0 0
coeff1 0
coeff2 25195908475657893494027183240048397689940557347513054227947345557770262917184
)";

TIACParams setupParams() {
    TIACParams params;

    pbc_param_t pbcParams;
    if (pbc_param_init_set_buf(pbcParams, BN256_PARAM, std::strlen(BN256_PARAM)) != 0) {
        throw std::runtime_error("Failed to initialize PBC parameters");
    }
    if (pairing_init_pbc_param(params.pairing, pbcParams) != 0) {
        throw std::runtime_error("Failed to initialize pairing");
    }
    pbc_param_clear(pbcParams);

    element_init_G1(params.g1, params.pairing);
    element_init_G1(params.h1, params.pairing);
    element_init_G2(params.g2, params.pairing);
    element_init_GT(params.gT, params.pairing);

    element_random(params.g1);
    element_random(params.h1);
    element_random(params.g2);

    element_pairing(params.gT, params.g1, params.g2);

    if (element_is1(params.gT)) {
        throw std::runtime_error("Pairing resulted in identity element in GT!");
    }

    mpz_init_set(params.prime_order, params.pairing->r);

    return params;
}

void clearParams(TIACParams& params) {
    element_clear(params.g1);
    element_clear(params.h1);
    element_clear(params.g2);
    element_clear(params.gT);
    mpz_clear(params.prime_order);
    pairing_clear(params.pairing);
}

void hashG1(element_t out, element_t in) {
    int len = element_length_in_bytes(in);
    unsigned char* buffer = new unsigned char[len];
    element_to_bytes(buffer, in);
    element_from_hash(out, buffer, len);
    delete[] buffer;
}