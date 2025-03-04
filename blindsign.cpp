#include "blindsign.h"
#include <openssl/sha.h>
#include <vector>
#include <sstream>
#include <iomanip>
#include <stdexcept>
#include <numeric>
#include <algorithm>

// Yardımcı: element_t değerini hex string’e çevirir.
static std::string elemToStrG1(element_t elem) {
    int len = element_length_in_bytes(elem);
    std::vector<unsigned char> buf(len);
    element_to_bytes(buf.data(), elem);

    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (unsigned char c : buf) {
        oss << std::setw(2) << (int)c;
    }
    return oss.str();
}

// Yardımcı: string’lerin birleşiminden hash oluşturur ve outZr’ye aktarır.
static void hashToZr(element_t outZr, TIACParams &params, const std::vector<std::string> &strs) {
    std::ostringstream oss;
    for (const auto &s : strs) {
        oss << s;
    }
    std::string data = oss.str();
    unsigned char digest[SHA512_DIGEST_LENGTH];
    SHA512(reinterpret_cast<const unsigned char*>(data.data()), data.size(), digest);

    mpz_t tmp;
    mpz_init(tmp);
    mpz_import(tmp, SHA512_DIGEST_LENGTH, 1, 1, 0, 0, digest);
    mpz_mod(tmp, tmp, params.prime_order);
    element_set_mpz(outZr, tmp);
    mpz_clear(tmp);
}

/*
  CheckKoR: Algoritma 6 (Temsil Bilgisinin İspatının Kontrolü)
  Bu fonksiyonda;
    comi_double = g1^(s1) · h1^(s2) · comi^(c)
    com_double  = g1^(s3) · h^(s2) · com^(c)
    c' = Hash(g1, h, h1, com, com_double, comi, comi_double)
  Eğer c' == c (πs içindeki c) ise ispat geçerli kabul edilir.
  Tüm ara değerler debug_info içine yazılır.
*/
bool CheckKoR(
    TIACParams &params,
    element_t com,
    element_t comi,
    element_t h,
    KoRProof &pi_s,
    std::string &debug_info
) {
    std::ostringstream dbg;
    // comi_double hesaplanıyor:
    element_t comi_double;
    element_init_G1(comi_double, params.pairing);
    element_t g1_s1; 
    element_init_G1(g1_s1, params.pairing);
    element_pow_zn(g1_s1, params.g1, pi_s.s1);
    
    element_t h1_s2; 
    element_init_G1(h1_s2, params.pairing);
    element_pow_zn(h1_s2, params.h1, pi_s.s2);
    
    element_t comi_c; 
    element_init_G1(comi_c, params.pairing);
    element_pow_zn(comi_c, comi, pi_s.c);
    
    element_mul(comi_double, g1_s1, h1_s2);
    element_mul(comi_double, comi_double, comi_c);
    
    dbg << "comi_double = " << elemToStrG1(comi_double) << "\n";
    
    element_clear(g1_s1);
    element_clear(h1_s2);
    element_clear(comi_c);
    
    // com_double hesaplanıyor:
    element_t com_double;
    element_init_G1(com_double, params.pairing);
    element_t g1_s3;
    element_init_G1(g1_s3, params.pairing);
    element_pow_zn(g1_s3, params.g1, pi_s.s3);
    
    element_t h_s2;
    element_init_G1(h_s2, params.pairing);
    element_pow_zn(h_s2, h, pi_s.s2);
    
    element_t com_c;
    element_init_G1(com_c, params.pairing);
    element_pow_zn(com_c, com, pi_s.c);
    
    element_mul(com_double, g1_s3, h_s2);
    element_mul(com_double, com_double, com_c);
    
    dbg << "com_double = " << elemToStrG1(com_double) << "\n";
    
    element_clear(g1_s3);
    element_clear(h_s2);
    element_clear(com_c);
    
    // c' hesaplanıyor:
    element_t cprime;
    element_init_Zr(cprime, params.pairing);
    std::vector<std::string> vec;
    vec.push_back(elemToStrG1(params.g1));
    vec.push_back(elemToStrG1(h));
    vec.push_back(elemToStrG1(params.h1));
    vec.push_back(elemToStrG1(com));
    vec.push_back(elemToStrG1(com_double));
    vec.push_back(elemToStrG1(comi));
    vec.push_back(elemToStrG1(comi_double));
    
    hashToZr(cprime, params, vec);
    dbg << "Computed cprime = " << elemToStrG1(cprime) << "\n";
    dbg << "pi_s.c        = " << elemToStrG1(pi_s.c) << "\n";
    
    bool ok = (element_cmp(cprime, pi_s.c) == 0);
    if(ok)
        dbg << "CheckKoR: PASSED\n";
    else
        dbg << "CheckKoR: FAILED\n";
    
    debug_info = dbg.str();
    
    element_clear(comi_double);
    element_clear(com_double);
    element_clear(cprime);
    
    return ok;
}

/*
  blindSign: Algoritma 12 TIAC Kör İmzalama
  - İlk olarak CheckKoR ile imza öncesi ispat kontrolü yapılır. (Debug bilgileri toplanır.)
  - Ardından, Hash(comi) hesaplanıp h ile karşılaştırılır.
  - Eğer ispatlar doğru ise, cm = h^(xm) · com^(ym) hesaplanır.
  Tüm ara hesaplamalar BlindSignDebug yapısına aktarılır.
*/
BlindSignature blindSign(
    TIACParams &params,
    PrepareBlindSignOutput &bsOut,
    mpz_t xm,
    mpz_t ym
) {
    BlindSignature sig;
    BlindSignDebug dbg;
    std::ostringstream debug_stream;
    
    // 1) CheckKoR
    std::string checkKoR_debug;
    bool ok = CheckKoR(params, bsOut.com, bsOut.comi, bsOut.h, bsOut.pi_s, checkKoR_debug);
    dbg.checkKoR_result = checkKoR_debug;
    if (!ok) {
        throw std::runtime_error("blindSign: CheckKoR failed. Debug:\n" + checkKoR_debug);
    }
    
    // 2) Hash(comi) hesapla ve h ile karşılaştır
    std::string computed_hash = elemToStrG1(bsOut.comi);
    dbg.computed_hash_comi = computed_hash;
    if (computed_hash != elemToStrG1(bsOut.h)) {
        throw std::runtime_error("blindSign: Hash(comi) != h. Computed: " + computed_hash +
                                   " vs h: " + elemToStrG1(bsOut.h));
    }
    
    // 3) Blind imzalama işlemi: cm = h^(xm) · com^(ym)
    // h zaten bsOut.h
    element_init_G1(sig.h, params.pairing);
    element_set(sig.h, bsOut.h);
    
    // hx = h^(xm)
    element_t hx;
    element_init_G1(hx, params.pairing);
    {
        element_t exp;
        element_init_Zr(exp, params.pairing);
        element_set_mpz(exp, xm);
        element_pow_zn(hx, bsOut.h, exp);
        element_clear(exp);
    }
    dbg.hx = elemToStrG1(hx);
    
    // comy = com^(ym)
    element_t comy;
    element_init_G1(comy, params.pairing);
    {
        element_t exp;
        element_init_Zr(exp, params.pairing);
        element_set_mpz(exp, ym);
        element_pow_zn(comy, bsOut.com, exp);
        element_clear(exp);
    }
    dbg.comy = elemToStrG1(comy);
    
    // cm = hx * comy
    element_init_G1(sig.cm, params.pairing);
    element_mul(sig.cm, hx, comy);
    dbg.computed_cm = elemToStrG1(sig.cm);
    
    element_clear(hx);
    element_clear(comy);
    
    sig.debug = dbg;
    return sig;
}
