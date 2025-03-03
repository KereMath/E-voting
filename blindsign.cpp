#include "blindsign.h"
#include <stdexcept>
#include <vector>
#include <sstream>
#include <iomanip>
#include <openssl/sha.h>

/*
  blindSign: 
    sig.h = bsOut.h
    sig.cm = (bsOut.h)^x * (bsOut.com)^y
*/
BlindSignature blindSign(
    TIACParams &params,
    PrepareBlindSignOutput &bsOut,
    mpz_t x,
    mpz_t y
) {
    // optional: check that Hash(comi) == h
    {
        element_t checkH;
        element_init_G1(checkH, params.pairing);

        // replicate hashing comi => checkH
        int len = element_length_in_bytes(bsOut.comi);
        std::vector<unsigned char> buf(len);
        element_to_bytes(buf.data(), bsOut.comi);

        std::ostringstream oss;
        oss << std::hex << std::setfill('0');
        for(auto c : buf) {
            oss << std::setw(2) << (int)c;
        }
        std::string data = oss.str();

        element_from_hash(checkH, data.data(), data.size());
        if (element_cmp(checkH, bsOut.h) != 0) {
            element_clear(checkH);
            throw std::runtime_error("blindSign: Hash(comi) != h => error");
        }
        element_clear(checkH);
    }

    BlindSignature sig;
    element_init_G1(sig.h,  params.pairing);
    element_init_G1(sig.cm, params.pairing);

    // sig.h = bsOut.h
    element_set(sig.h, bsOut.h);

    // sig.cm = h^x * com^y
    element_t hx, comy;
    element_init_G1(hx,   params.pairing);
    element_init_G1(comy, params.pairing);

    // exponent
    element_t expx, expy;
    element_init_Zr(expx, params.pairing);
    element_init_Zr(expy, params.pairing);

    element_set_mpz(expx, x);
    element_set_mpz(expy, y);

    // hx = (bsOut.h)^x
    element_pow_zn(hx, bsOut.h, expx);
    // comy = (bsOut.com)^y
    element_pow_zn(comy, bsOut.com, expy);

    // cm = hx * comy
    element_mul(sig.cm, hx, comy);

    // cleanup
    element_clear(hx);
    element_clear(comy);
    element_clear(expx);
    element_clear(expy);

    return sig;
}
