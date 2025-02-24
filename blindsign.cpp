#include "blindsign.h"
#include <openssl/sha.h>
#include <sstream>
#include <iomanip>
#include <vector>
#include <stdexcept>

/*
  PBC parametreleri "params" => g1, h1, prime_order, pairing
  Eleman tipleri element_t => struct element_s[1]
*/

////////////////////////////////////
// Yardımcı Fonksiyonlar
////////////////////////////////////

// G1 -> hex string
static std::string elemToStrG1(element_t g1Elem) {
    int length = element_length_in_bytes(g1Elem);
    std::vector<unsigned char> buf(length);
    element_to_bytes(buf.data(), g1Elem);

    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for(unsigned char c : buf) {
        oss << std::setw(2) << (int)c;
    }
    return oss.str();
}

// Bir dizi G1 elemanini string'e dönüştürüp SHA-512 -> Zr
static void hashToZr(element_t outZr, TIACParams &params, const std::vector<element_t> &g1Elems)
{
    std::ostringstream oss;
    for(auto &e : g1Elems) {
        oss << elemToStrG1(e);
    }
    std::string msg = oss.str();

    unsigned char digest[SHA512_DIGEST_LENGTH];
    SHA512((const unsigned char*)msg.data(), msg.size(), digest);

    mpz_t tmp;
    mpz_init(tmp);
    mpz_import(tmp, SHA512_DIGEST_LENGTH, 1, 1, 0, 0, digest);
    mpz_mod(tmp, tmp, params.prime_order);

    element_set_mpz(outZr, tmp);
    mpz_clear(tmp);
}

////////////////////////////////////
// 1) CheckKoR (Alg.6)
////////////////////////////////////
bool CheckKoR(
    TIACParams &params,
    element_t com,
    element_t comi,
    element_t h,
    KoRProof &pi_s
) {
    // pi_s = (c, s1, s2, s3)
    // 1) com''i = g1^s1 * h1^s2 * comi^c
    element_t comi_dprime;
    element_init_G1(comi_dprime, params.pairing);

    // g1^s1
    element_t g1_s1;
    element_init_G1(g1_s1, params.pairing);
    element_pow_zn(g1_s1, params.g1, pi_s.s1);

    // h1^s2
    element_t h1_s2;
    element_init_G1(h1_s2, params.pairing);
    element_pow_zn(h1_s2, params.h1, pi_s.s2);

    // comi^c
    element_t comi_c;
    element_init_G1(comi_c, params.pairing);
    element_pow_zn(comi_c, comi, pi_s.c);

    // comi_dprime = g1_s1 * h1_s2
    element_mul(comi_dprime, g1_s1, h1_s2);
    element_clear(g1_s1);
    element_clear(h1_s2);

    // comi_dprime *= comi_c
    element_mul(comi_dprime, comi_dprime, comi_c);
    element_clear(comi_c);

    // 2) com'' = g1^s3 * h^s2 * com^c
    element_t com_dprime;
    element_init_G1(com_dprime, params.pairing);

    // g1^s3
    element_t g1_s3;
    element_init_G1(g1_s3, params.pairing);
    element_pow_zn(g1_s3, params.g1, pi_s.s3);

    // h^s2
    element_t h_s2;
    element_init_G1(h_s2, params.pairing);
    element_pow_zn(h_s2, h, pi_s.s2);

    // com^c
    element_t com_c;
    element_init_G1(com_c, params.pairing);
    element_pow_zn(com_c, com, pi_s.c);

    // com_dprime = g1_s3 * h_s2
    element_mul(com_dprime, g1_s3, h_s2);
    element_clear(g1_s3);
    element_clear(h_s2);

    // com_dprime *= com_c
    element_mul(com_dprime, com_dprime, com_c);
    element_clear(com_c);

    // 3) c' = Hash( g1, h, h1, com, com_dprime, comi, comi_dprime ) -> Zr
    element_t cprime;
    element_init_Zr(cprime, params.pairing);

    std::vector<element_t> groupElems(7);
    // her element_t init & set
    element_init_G1(groupElems[0], params.pairing); // g1
    element_set(groupElems[0], params.g1);

    element_init_G1(groupElems[1], params.pairing); // h
    element_set(groupElems[1], h);

    element_init_G1(groupElems[2], params.pairing); // h1
    element_set(groupElems[2], params.h1);

    element_init_G1(groupElems[3], params.pairing); // com
    element_set(groupElems[3], com);

    element_init_G1(groupElems[4], params.pairing); // com_dprime
    element_set(groupElems[4], com_dprime);

    element_init_G1(groupElems[5], params.pairing); // comi
    element_set(groupElems[5], comi);

    element_init_G1(groupElems[6], params.pairing); // comi_dprime
    element_set(groupElems[6], comi_dprime);

    hashToZr(cprime, params, groupElems);

    // Temizlik
    for(int i=0; i<7; i++){
        element_clear(groupElems[i]);
    }
    element_clear(comi_dprime);
    element_clear(com_dprime);

    // c' == pi_s.c ?
    if(element_cmp(cprime, pi_s.c) != 0) {
        element_clear(cprime);
        return false;
    }
    element_clear(cprime);
    return true;
}

////////////////////////////////////
// 2) blindSign (Alg.12)
////////////////////////////////////
BlindSignature blindSign(
    TIACParams &params,
    PrepareBlindSignOutput &bsOut,
    mpz_t xm,
    mpz_t ym
) {
    // 1) KoR check
    bool ok = CheckKoR(params, bsOut.com, bsOut.comi, bsOut.h, bsOut.pi_s);
    if(!ok) {
        throw std::runtime_error("blindSign: KoR check failed (Alg.6).");
    }

    // 2) if Hash(comi) != h => hata
    //    HashInG1(comi)
    element_t hprime;
    element_init_G1(hprime, params.pairing);
    {
        // comi -> hex
        std::string s = elemToStrG1(bsOut.comi);
        element_from_hash(hprime, s.data(), s.size());
    }
    if(element_cmp(hprime, bsOut.h) != 0) {
        element_clear(hprime);
        throw std::runtime_error("blindSign: Hash(comi) != h => hata.");
    }
    element_clear(hprime);

    // 3) cm = h^xm * com^ym
    BlindSignature outSig;
    element_init_G1(outSig.h, params.pairing);
    element_init_G1(outSig.cm, params.pairing);

    // outSig.h = bsOut.h
    element_set(outSig.h, bsOut.h);

    // h^xm
    element_t hx;
    element_init_G1(hx, params.pairing);
    {
        element_t expX;
        element_init_Zr(expX, params.pairing);
        element_set_mpz(expX, xm);   // xm => Zr
        element_pow_zn(hx, bsOut.h, expX);
        element_clear(expX);
    }

    // com^ym
    element_t comy;
    element_init_G1(comy, params.pairing);
    {
        element_t expY;
        element_init_Zr(expY, params.pairing);
        element_set_mpz(expY, ym);   // ym => Zr
        element_pow_zn(comy, bsOut.com, expY);
        element_clear(expY);
    }

    // cm = hx * comy
    element_mul(outSig.cm, hx, comy);

    element_clear(hx);
    element_clear(comy);

    return outSig; // (h, cm)
}
