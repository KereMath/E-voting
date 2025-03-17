#include "provecredential.h"
#include <openssl/sha.h>
#include <sstream>
#include <iomanip>
#include <stdexcept>
#include <iostream>
#include <vector>

extern std::string elementToStringG1(const element_t elem);

static std::string elementToStringG2(const element_t elem) {
    element_t elem_nonconst;
    elem_nonconst[0] = *((element_s*)(&elem[0]));
    int len = element_length_in_bytes(elem_nonconst);
    std::vector<unsigned char> buf(len);
    element_to_bytes(buf.data(), elem_nonconst);
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (unsigned char c : buf) {
        oss << std::setw(2) << (int)c;
    }
    return oss.str();
}

static std::string mpzToString(const mpz_t value) {
    char* c_str = mpz_get_str(nullptr, 10, value);
    std::string str(c_str);
    free(c_str);
    return str;
}

ProveCredentialOutput proveCredential(TIACParams &params,AggregateSignature &aggSig,MasterVerKey &mvk,const std::string &didStr,const mpz_t o   ) {
    ProveCredentialOutput output;
    element_t r, r_prime;
    element_init_Zr(r, params.pairing);
    element_init_Zr(r_prime, params.pairing);
    element_random(r);
    element_random(r_prime);
    element_t h_dbl;
    element_init_G1(h_dbl, params.pairing);
    element_pow_zn(h_dbl, aggSig.h, r_prime);
    element_t s_rprime, h_pp_r, s_dbl;
    element_init_G1(s_rprime, params.pairing);
    element_init_G1(h_pp_r, params.pairing);
    element_init_G1(s_dbl, params.pairing);
    element_pow_zn(s_rprime, aggSig.s, r_prime);
    element_pow_zn(h_pp_r, h_dbl, r);
    element_mul(s_dbl, s_rprime, h_pp_r);
    element_init_G1(output.sigmaRnd.h, params.pairing);
    element_set(output.sigmaRnd.h, h_dbl);
    element_init_G1(output.sigmaRnd.s, params.pairing);
    element_set(output.sigmaRnd.s, s_dbl);
    mpz_t didInt;
    mpz_init(didInt);
    if (mpz_set_str(didInt, didStr.c_str(), 16) != 0)
        throw std::runtime_error("proveCredential: Invalid DID hex string");
    mpz_mod(didInt, didInt, params.prime_order);
    element_t beta_exp, g2_r;
    element_init_G2(beta_exp, params.pairing);  
    element_t expElem;
    element_init_Zr(expElem, params.pairing);
    element_set_mpz(expElem, didInt);
    element_pow_zn(beta_exp, mvk.beta2, expElem);
    element_clear(expElem);
    element_init_G2(g2_r, params.pairing);  
    element_pow_zn(g2_r, params.g2, r);
    element_init_G2(output.k, params.pairing);  
    element_mul(output.k, mvk.alpha2, beta_exp);
    element_mul(output.k, output.k, g2_r);
    std::ostringstream dbg;
    dbg << "h'' = " << elementToStringG1(output.sigmaRnd.h) << "\n";
    dbg << "s'' = " << elementToStringG1(output.sigmaRnd.s) << "\n";
    dbg << "k   = " << elementToStringG2(output.k) << "\n"; 
    output.sigmaRnd.debug_info = dbg.str();
    element_init_Zr(output.c, params.pairing);
    element_init_Zr(output.s1, params.pairing);
    element_init_Zr(output.s2, params.pairing);
    element_init_Zr(output.s3, params.pairing);
    element_init_Zr(output.r, params.pairing);
    element_set(output.r, r);
    element_clear(r);
    element_clear(r_prime);
    element_clear(h_dbl);
    element_clear(s_rprime);
    element_clear(h_pp_r);
    element_clear(s_dbl);
    element_clear(beta_exp);
    element_clear(g2_r);
    mpz_clear(didInt);
    return output;
}