#include "blindsign.h"
#include <stdexcept>
#include <chrono>
#include <sstream>
#include <iomanip>
#include <openssl/sha.h>
#include <vector>

// Helper: Convert an element in G1 to a hexadecimal string.
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

// Helper: Hash a G1 element by converting it to hex and mapping it to G1.
static void hashComiToG1(element_t outG1, TIACParams &params, element_t comi) {
    std::string hexStr = elementToHex(comi);
    element_from_hash(outG1, hexStr.data(), hexStr.size());
}

BlindSignature blindSign(
    TIACParams &params,
    PrepareBlindSignOutput &bsOut,
    mpz_t xm, // EA's secret key (xₘ)
    mpz_t ym  // (currently unused)
) {
    BlindSignature sig;
    element_init_G1(sig.h, params.pairing);
    element_init_G1(sig.cm, params.pairing);

    // Set h = Hash(comi)
    element_t h;
    element_init_G1(h, params.pairing);
    hashComiToG1(h, params, bsOut.comi);
    element_set(sig.h, h);
    element_clear(h);

    // Compute cm = (bsOut.com_blind)^(xₘ)
    element_t expX;
    element_init_Zr(expX, params.pairing);
    element_set_mpz(expX, xm);
    element_pow_zn(sig.cm, bsOut.com_blind, expX);
    element_clear(expX);

    return sig;
}
