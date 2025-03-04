#include "blindsign.h"
#include <openssl/sha.h>
#include <vector>
#include <sstream>
#include <iomanip>
#include <stdexcept>
#include <iostream>
#include <numeric>
#include <algorithm>

// elemToStrG1 artık global olarak tanımlı (static kaldırıldı)
std::string elemToStrG1(element_t elem) {
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

// Birden fazla element'in string gösterimlerini birleştirip hash hesaplar
static void hashToZr(element_t outZr, TIACParams &params, const std::vector<element_s*> &g1Elems) {
    std::ostringstream oss;
    for (auto ePtr : g1Elems) {
        oss << elemToStrG1(ePtr);
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
  Hesaplamalar:
    comi_double = g1^(s1) · h1^(s2) · comi^(c)
    com_double  = g1^(s3) · h^(s2) · com^(c)
    cprime = Hash(g1, h, h1, com, com_double, comi, comi_double)
  Ara değerler ekrana yazdırılır.
*/
bool CheckKoR(
    TIACParams &params,
    element_t com,
    element_t comi,
    element_t h,
    KoRProof &pi_s
) {
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
    element_clear(g1_s1);
    element_clear(h1_s2);

    element_mul(comi_double, comi_double, comi_c);
    element_clear(comi_c);

    std::cout << "[DEBUG] comi_double = " << elemToStrG1(comi_double) << "\n";

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

    element_clear(g1_s3);
    element_clear(h_s2);
    element_clear(com_c);

    std::cout << "[DEBUG] com_double = " << elemToStrG1(com_double) << "\n";

    // cprime hesaplanıyor:
    element_t cprime;
    element_init_Zr(cprime, params.pairing);

    std::vector<element_s*> toHash;
    toHash.reserve(7);
    toHash.push_back(params.g1);
    toHash.push_back(h);
    toHash.push_back(params.h1);
    toHash.push_back(com);
    toHash.push_back(com_double);
    toHash.push_back(comi);
    toHash.push_back(comi_double);

    hashToZr(cprime, params, toHash);

    std::cout << "[DEBUG] Computed cprime = " << elemToStrG1(cprime) << "\n";
    std::cout << "[DEBUG] pi_s.c         = " << elemToStrG1(pi_s.c) << "\n";

    bool ok = (element_cmp(cprime, pi_s.c) == 0);
    if(ok)
        std::cout << "[DEBUG] CheckKoR PASSED\n";
    else
        std::cout << "[DEBUG] CheckKoR FAILED\n";

    element_clear(comi_double);
    element_clear(com_double);
    element_clear(cprime);
    return ok;
}

/*
  blindSign: Algoritma 12 TIAC Kör İmzalama
  Hesaplamalar:
    1) CheckKoR çağrılarak imza ispatı doğrulanır.
    2) Hash(comi) fonksiyonu ile h değeri üretilir ve kontrol edilir.
    3) cm = h^(xm) · com^(ym) hesaplanır.
  Ek olarak, adminId ve voterId parametreleri ile hangi adminin ve seçmenin
  imzayı ürettiği bilgisi de debug alanında saklanır.
*/
BlindSignature blindSign(
    TIACParams &params,
    PrepareBlindSignOutput &bsOut,
    mpz_t xm,
    mpz_t ym,
    int adminId,
    int voterId
) {
    // 1) CheckKoR
    bool ok = CheckKoR(params, bsOut.com, bsOut.comi, bsOut.h, bsOut.pi_s);
    if(!ok) {
        throw std::runtime_error("blindSign: KoR check failed");
    }

    // 2) Hash(comi) hesapla ve bsOut.h ile karşılaştır
    element_t hprime;
    element_init_G1(hprime, params.pairing);
    {
        std::string s = elemToStrG1(bsOut.comi);
        element_from_hash(hprime, s.data(), s.size());
    }
    std::cout << "[DEBUG] hprime (Hash(comi)) = " << elemToStrG1(hprime) << "\n";
    std::cout << "[DEBUG] bsOut.h              = " << elemToStrG1(bsOut.h) << "\n";
    if(element_cmp(hprime, bsOut.h) != 0) {
        element_clear(hprime);
        throw std::runtime_error("blindSign: Hash(comi) != h => hata");
    }
    element_clear(hprime);

    BlindSignature sig;
    element_init_G1(sig.h,  params.pairing);
    element_init_G1(sig.cm, params.pairing);

    // h aynen kullanılıyor
    element_set(sig.h, bsOut.h);

    // 3) hx = h^(xm)
    element_t hx;
    element_init_G1(hx, params.pairing);
    {
        element_t expX;
        element_init_Zr(expX, params.pairing);
        element_set_mpz(expX, xm);
        element_pow_zn(hx, bsOut.h, expX);
        element_clear(expX);
    }
    std::cout << "[DEBUG] hx = h^(xm) = " << elemToStrG1(hx) << "\n";

    // comy = com^(ym)
    element_t comy;
    element_init_G1(comy, params.pairing);
    {
        element_t expY;
        element_init_Zr(expY, params.pairing);
        element_set_mpz(expY, ym);
        element_pow_zn(comy, bsOut.com, expY);
        element_clear(expY);
    }
    std::cout << "[DEBUG] comy = com^(ym) = " << elemToStrG1(comy) << "\n";

    // cm = hx * comy
    element_mul(sig.cm, hx, comy);
    std::cout << "[DEBUG] Computed cm = " << elemToStrG1(sig.cm) << "\n";

    element_clear(hx);
    element_clear(comy);

    // Debug bilgilerine admin ve voter bilgisini ekliyoruz.
    sig.debug.adminId = adminId;
    sig.debug.voterId = voterId;
    sig.debug.computed_hash_comi = ""; // İsteğe bağlı olarak eklenebilir.
    sig.debug.hx = "";  // İsteğe bağlı
    sig.debug.comy = ""; // İsteğe bağlı
    sig.debug.computed_cm = elemToStrG1(sig.cm);

    return sig;
}
