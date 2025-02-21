// setup.cpp
#include "setup.h"
#include <stdexcept>
#include <string>

static const char* BN256_PARAM = R"(
type d
q 25451229125838931816532161417680598543386368531494515945851210512836528987393
r 25451229125838931816532161417680598543386368531494515945851210512836526359041
h 315113925988032513224249117698304
b 3
k 6
nk 152707374755033590899192968505883591260318211188967095674907263077019171954241
nq 50811258251677863633064322835361197086772737062989031891702421025673052718143
)";

TIACParams setupParams() {
    TIACParams params;

    pbc_param_t pbcParams;
    pbc_param_init_set_buf(pbcParams, BN256_PARAM, std::strlen(BN256_PARAM));
    pairing_init_pbc_param(params.pairing, pbcParams);
    pbc_param_clear(pbcParams);

    element_init_G1(params.g1, params.pairing);
    element_init_G1(params.h1, params.pairing);
    element_init_G2(params.g2, params.pairing);
    element_init_GT(params.gT, params.pairing);

    // Generate random non-identity elements
    element_random(params.g1);
    element_random(params.h1);
    element_random(params.g2);

    // Compute GT generator
    element_pairing(params.gT, params.g1, params.g2);

    // Check if pairing result is non-trivial
    if (element_is1(params.gT)) {
        throw std::runtime_error("Pairing resulted in identity element in GT!");
    }

    mpz_init_set(params.prime_order, params.pairing->r);

    return params;
}

void clearParams(TIACParams& params) { // Fixed typo: ¶ms -> params
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