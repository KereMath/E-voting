#include "blindsign.h"
#include <openssl/sha.h>
#include <vector>
#include <sstream>
#include <iomanip>
#include <stdexcept>

/*
  Hatırlatma: 
   element_t = struct element_s[1]
   Aşağıdaki fonksiyonlarda PBC fonksiyonlarını kullanırken 
   'com' -> (element_s*) decay, vb.
*/

// Yardımcı: G1 -> hex string
static std::string elemToStrG1(element_t g1Elem) {
    int len = element_length_in_bytes(g1Elem);
    std::vector<unsigned char> buf(len);
    element_to_bytes(buf.data(), g1Elem);

    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for(auto c : buf) {
        oss << std::setw(2) << (int)c;
    }
    return oss.str();
}

// Hash fonksiyonu (G1 elemanlarından concat -> SHA512 -> mod p)
static void hashToZr(element_t outZr, TIACParams &params, 
                     const std::vector<element_t> &elems)
{
    // Elems => G1'lerin concat
    std::ostringstream oss;
    for(auto &e : elems) {
        oss << elemToStrG1(e);
    }
    std::string msg = oss.str();

    unsigned char digest[SHA512_DIGEST_LENGTH];
    SHA512((unsigned char*)msg.data(), msg.size(), digest);

    mpz_t tmp;
    mpz_init(tmp);
    mpz_import(tmp, SHA512_DIGEST_LENGTH, 1, 1, 0, 0, digest);
    mpz_mod(tmp, tmp, params.prime_order);

    element_set_mpz(outZr, tmp);
    mpz_clear(tmp);
}

/*
  CheckKoR (Alg. 6)
   Girdi: 
     - (com, comi, h), pi_s=(c,s1,s2,s3), g1, h1
   1) com''i = g1^s1 * h1^s2 * comi^c
   2) com''  = g1^s3 * h^s2  * com^c
   3) c' = Hash(g1, h, h1, com, com'' , comi, com''i)
   4) if c' != c => false else => true
*/
bool CheckKoR(
    TIACParams &params,
    const element_t com,
    const element_t comi,
    const element_t h,
    const KoRProof &pi_s
) {
    // (c, s1, s2, s3) in pi_s
    // g1, h1 from params
    // p, prime_order also in params

    // 1) com''_i
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

    // com''i = g1_s1 * h1_s2
    element_mul(comi_dprime, g1_s1, h1_s2);
    // com''i *= comi_c
    element_mul(comi_dprime, comi_dprime, comi_c);

    element_clear(g1_s1);
    element_clear(h1_s2);
    element_clear(comi_c);

    // 2) com'' 
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

    // com'' = g1_s3 * h_s2 * com_c
    element_mul(com_dprime, g1_s3, h_s2);
    element_mul(com_dprime, com_dprime, com_c);

    element_clear(g1_s3);
    element_clear(h_s2);
    element_clear(com_c);

    // 3) c' = Hash(g1, h, h1, com, com'' , comi, com''i) -> Zr
    element_t cprime;
    element_init_Zr(cprime, params.pairing);

    // elems: g1, h, h1, com, com_dprime, comi, comi_dprime
    std::vector<element_t> g1s(7);
    // kopyalama: g1 => g1s[0], h => g1s[1], ...
    element_init_same_as(g1s[0], params.g1);
    element_set(g1s[0], params.g1);

    element_init_same_as(g1s[1], h);
    element_set(g1s[1], h);

    element_init_same_as(g1s[2], params.h1);
    element_set(g1s[2], params.h1);

    element_init_same_as(g1s[3], com);
    element_set(g1s[3], com);

    element_init_same_as(g1s[4], com_dprime);
    element_set(g1s[4], com_dprime);

    element_init_same_as(g1s[5], comi);
    element_set(g1s[5], comi);

    element_init_same_as(g1s[6], comi_dprime);
    element_set(g1s[6], comi_dprime);

    hashToZr(cprime, params, g1s);

    // Temizlik
    for (int i=0; i<7; i++){
        element_clear(g1s[i]);
    }
    element_clear(comi_dprime);
    element_clear(com_dprime);

    // c' == c ?
    // c in pi_s.c
    if(element_cmp(cprime, pi_s.c) != 0) {
        element_clear(cprime);
        return false;
    }
    element_clear(cprime);
    return true;
}

/*
  blindSign (Algoritma 12)
   Girdi: 
    - PrepareBlindSignOutput (com, comi, h, pi_s)
    - (xm, ym) => otoritenin gizli anahtarı
   1) CheckKoR(...) != true => "Hata"
   2) if Hash(comi) != h => "Hata"
   3) cm = h^xm * com^ym
   4) return (h, cm)
*/
BlindSignature blindSign(
    TIACParams &params,
    const PrepareBlindSignOutput &bsOut,
    const mpz_t xm,
    const mpz_t ym
) {
    // 1) KoR kontrol
    bool ok = CheckKoR(params, bsOut.com, bsOut.comi, bsOut.h, bsOut.pi_s);
    if(!ok) {
        throw std::runtime_error("blindSign: KoR check failed (Alg.6)");
    }

    // 2) if Hash(comi) != h => "Hata"
    //    comi => G1 => hashInG1 ? 
    //    Aynı mantık: h' = HashInG1(comi), 
    //    if h' != bsOut.h => hata
    element_t hprime;
    element_init_G1(hprime, params.pairing);

    // "hashToG1" benzeri
    {
        std::string s = elemToStrG1(bsOut.comi);
        element_from_hash(hprime, s.data(), s.size());
    }
    if(element_cmp(hprime, bsOut.h) != 0) {
        element_clear(hprime);
        throw std::runtime_error("blindSign: Hash(comi)!=h => Hata");
    }
    element_clear(hprime);

    // 3) cm = h^xm * com^ym
    BlindSignature sig;
    element_init_G1(sig.h, params.pairing);
    element_init_G1(sig.cm, params.pairing);

    // sig.h = bsOut.h (kopyalayacağız)
    element_set(sig.h, bsOut.h);

    // cm = h^xm * com^ym
    // h^xm
    element_t hx;
    element_init_G1(hx, params.pairing);
    {
        element_t expX;
        element_init_Zr(expX, params.pairing);
        element_set_mpz(expX, xm);
        element_pow_zn(hx, bsOut.h, expX);
        element_clear(expX);
    }

    // com^ym
    element_t comy;
    element_init_G1(comy, params.pairing);
    {
        element_t expY;
        element_init_Zr(expY, params.pairing);
        element_set_mpz(expY, ym);
        element_pow_zn(comy, bsOut.com, expY);
        element_clear(expY);
    }

    // cm = hx * comy
    element_mul(sig.cm, hx, comy);

    element_clear(hx);
    element_clear(comy);

    // return sig = (h, cm)
    return sig;
}
