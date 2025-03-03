#include "blindsign.h"
#include <openssl/sha.h>
#include <stdexcept>
#include <vector>
#include <sstream>
#include <iomanip>

/* Helper: convert G1 element to hex string */
static std::string elemToHexG1(element_t g) {
    int len = element_length_in_bytes(g);
    std::vector<unsigned char> buf(len);
    element_to_bytes(buf.data(), g);
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (auto c : buf) {
        oss << std::setw(2) << (int)c;
    }
    return oss.str();
}

/* CheckKoR: omitted for brevity, or define if you do KoR check from your code. */

BlindSignature blindSign(
    TIACParams &params,
    PrepareBlindSignOutput &bsOut,
    mpz_t x, // master exponent x
    mpz_t y  // master exponent y
) {
    // [Optional] Check KoR proof from prepareBlindSign if you want:
    //  bool ok = CheckKoR(...); if (!ok) throw ...

    // 1) Check Hash(comi) == h
    //    or just replicate your existing logic (like you do in your code):
    {
        // We'll do a small check, same as you do in unblind sign:
        element_t hcheck;
        element_init_G1(hcheck, params.pairing);

        // "Hash(comi)" => replicate how prepareBlindSign hashed comi
        int len = element_length_in_bytes(bsOut.comi);
        std::vector<unsigned char> temp(len);
        element_to_bytes(temp.data(), bsOut.comi);

        std::ostringstream oss;
        oss << std::hex << std::setfill('0');
        for (auto c : temp) { oss << std::setw(2) << (int)c; }
        std::string data = oss.str();

        element_from_hash(hcheck, data.data(), data.size());

        if (element_cmp(hcheck, bsOut.h) != 0) {
            element_clear(hcheck);
            throw std::runtime_error("blindSign: Hash(comi) != h => error");
        }
        element_clear(hcheck);
    }

    // 2) Build BlindSignature (h, cm)
    BlindSignature sig;
    element_init_G1(sig.h,  params.pairing);
    element_init_G1(sig.cm, params.pairing);

    //   a) sig.h = bsOut.h
    element_set(sig.h, bsOut.h);

    //   b) sig.cm = h^x * com^y
    element_t hx, comy;
    element_init_G1(hx,   params.pairing);
    element_init_G1(comy, params.pairing);

    // compute h^x
    {
        element_t expx;
        element_init_Zr(expx, params.pairing);
        element_set_mpz(expx, x);
        element_pow_zn(hx, bsOut.h, expx);
        element_clear(expx);
    }
    // compute com^y
    {
        element_t expy;
        element_init_Zr(expy, params.pairing);
        element_set_mpz(expy, y);
        element_pow_zn(comy, bsOut.com, expy);
        element_clear(expy);
    }
    // multiply => sig.cm
    element_mul(sig.cm, hx, comy);

    element_clear(hx);
    element_clear(comy);

    return sig;
}
