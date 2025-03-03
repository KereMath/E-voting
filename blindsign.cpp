#include "blindsign.h"
#include <stdexcept>
#include <chrono>
#include <sstream>
#include <iomanip>
#include <openssl/sha.h>
#include <vector>

// Helper: Convert a G1 element to a hex string.
static std::string elementToHex(element_t e) {
    int len = element_length_in_bytes(e);
    std::vector<unsigned char> buf(len);
    element_to_bytes(buf.data(), e);
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (unsigned char c : buf) {
        oss << std::setw(2) << (int)c;
    }
    return oss.str();
}

// Helper: Compute h = Hash(comi)
static void hashComiToG1(element_t outG1, TIACParams &params, element_t comi) {
    std::string hexStr = elementToHex(comi);
    element_from_hash(outG1, hexStr.data(), hexStr.size());
}

BlindSignature blindSign(
    TIACParams &params,
    PrepareBlindSignOutput &bsOut,
    mpz_t xm, // EA's private key (xₘ)
    mpz_t ym  // EA's private key (yₘ)
) {
    BlindSignature sig;
    element_init_G1(sig.h, params.pairing);
    element_init_G1(sig.cm, params.pairing);

    // Step 1: Compute h = Hash(comi)
    element_t h;
    element_init_G1(h, params.pairing);
    hashComiToG1(h, params, bsOut.comi);
    element_set(sig.h, h);
    element_clear(h);

    // Step 2: Compute cm = com^(xₘ) * g1^(yₘ * o)
    element_t expX, expY;
    element_init_Zr(expX, params.pairing);
    element_init_Zr(expY, params.pairing);
    element_set_mpz(expX, xm); // xₘ
    element_set_mpz(expY, ym); // yₘ

    element_pow_zn(sig.cm, bsOut.com, expX); // cm = com^(xₘ)

    // Add y_m * o term
    element_t g1_y_o;
    element_init_G1(g1_y_o, params.pairing);
    element_pow_zn(g1_y_o, params.h1, expY);
    element_mul(sig.cm, sig.cm, g1_y_o);

    // Cleanup
    element_clear(expX);
    element_clear(expY);
    element_clear(g1_y_o);

    return sig;
}
