#include "blindsign.h"
#include "common_utils.h"
#include <pbc/pbc.h>
#include <gmp.h>
#include <openssl/sha.h>
#include <sstream>
#include <iomanip>
#include <vector>
#include <iostream>

// CheckKoR (Algorithm 6)
// Girdi: params, com, comi, h, πs
// Hesaplamalar:
//   comp_i = g1^(s1) * h1^(s2) * comi^(c)
//   comp  = g1^(s3) * h^(s2) * com^(c)
//   c' = Hash(g1, h, h1, com, comp, comi, comp_i)
// Eğer c' == c, ispat başarılı.
bool checkKoR(TIACParams &params, element_t com, element_t comi, element_t h, Proof &pi_s) {
    element_t comp_i, comp;
    element_init_G1(comp_i, params.pairing);
    element_init_G1(comp, params.pairing);
    
    {
        element_t t1, t2, t3;
        element_init_G1(t1, params.pairing);
        element_init_G1(t2, params.pairing);
        element_init_G1(t3, params.pairing);
        element_pow_zn(t1, params.g1, pi_s.s1);
        element_pow_zn(t2, params.h1, pi_s.s2);
        element_pow_zn(t3, comi, pi_s.c);
        element_mul(comp_i, t1, t2);
        element_mul(comp_i, comp_i, t3);
        element_clear(t1); element_clear(t2); element_clear(t3);
    }
    
    {
        element_t t1, t2, t3;
        element_init_G1(t1, params.pairing);
        element_init_G1(t2, params.pairing);
        element_init_G1(t3, params.pairing);
        element_pow_zn(t1, params.g1, pi_s.s3);
        element_pow_zn(t2, h, pi_s.s2);
        element_pow_zn(t3, com, pi_s.c);
        element_mul(comp, t1, t2);
        element_mul(comp, comp, t3);
        element_clear(t1); element_clear(t2); element_clear(t3);
    }
    
    std::vector<std::string> hashData;
    hashData.push_back(elementToStr(params.g1));
    hashData.push_back(elementToStr(h));
    hashData.push_back(elementToStr(params.h1));
    hashData.push_back(elementToStr(com));
    hashData.push_back(elementToStr(comp));
    hashData.push_back(elementToStr(comi));
    hashData.push_back(elementToStr(comp_i));
    element_t c_prime;
    element_init_Zr(c_prime, params.pairing);
    hashVectorToZr(hashData, params, c_prime);
    
    bool valid = (element_cmp(c_prime, pi_s.c) == 0);
    
    element_clear(comp_i);
    element_clear(comp);
    element_clear(c_prime);
    return valid;
}

// blindSign (Algorithm 12)
// Girdi: blindOut (prepare blind sign çıktısı) ve voterin secret değerleri xm, ym
// Önce CheckKoR kontrolü yapılır; başarılı ise, cm = h^(xm) * g1^(ym) hesaplanır.
BlindSignature blindSign(TIACParams &params, BlindSignOutput &blindOut, element_t xm, element_t ym) {
    BlindSignature sig;
    
    // İlk olarak, kontrol için Hash(comi) yeniden hesaplanır.
    element_t h_prime;
    element_init_G1(h_prime, params.pairing);
    {
        std::string comiStr = elementToStr(blindOut.comi);
        hashToG1(comiStr, params, h_prime);
    }
    bool hashOk = (element_cmp(h_prime, blindOut.h) == 0);
    element_clear(h_prime);
    
    bool korOk = checkKoR(params, blindOut.com, blindOut.comi, blindOut.h, blindOut.pi_s);
    
    if (!hashOk || !korOk) {
        std::cerr << "Blind Sign Check Failed: KoR proof is invalid or Hash(comi) != h." << std::endl;
        element_init_G1(sig.h, params.pairing);
        element_set0(sig.h);
        element_init_G1(sig.cm, params.pairing);
        element_set0(sig.cm);
        return sig;
    }
    
    // Eğer kontrol başarılı ise, final blind signature üretimi:
    // cm = h^(xm) * g1^(ym)
    element_init_G1(sig.h, params.pairing);
    element_set(sig.h, blindOut.h);
    element_init_G1(sig.cm, params.pairing);
    {
        element_t t1, t2;
        element_init_G1(t1, params.pairing);
        element_init_G1(t2, params.pairing);
        element_pow_zn(t1, blindOut.h, xm);
        element_pow_zn(t2, params.g1, ym);
        element_mul(sig.cm, t1, t2);
        element_clear(t1);
        element_clear(t2);
    }
    
    return sig;
}
