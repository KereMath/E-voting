#include "blindsign.h"
#include <pbc/pbc.h>
#include <gmp.h>
#include <openssl/sha.h>
#include <sstream>
#include <iomanip>
#include <vector>
#include <iostream>

// --- Yardımcı Fonksiyonlar ---
// Element'in string temsilini döndürür.
std::string elementToStr(element_t e) {
    char buffer[1024];
    element_snprintf(buffer, sizeof(buffer), "%B", e);
    return std::string(buffer);
}

// Verilen stringi SHA-512 ile hash'ler ve sonucu Zₚ elemanına dönüştürür.
void hashStringToZr(const std::string &input, TIACParams &params, element_t result) {
    unsigned char hash[SHA512_DIGEST_LENGTH];
    SHA512(reinterpret_cast<const unsigned char*>(input.c_str()), input.size(), hash);
    std::stringstream ss;
    for (int i = 0; i < SHA512_DIGEST_LENGTH; i++) {
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
    }
    std::string hexStr = ss.str();
    mpz_t num;
    mpz_init(num);
    mpz_set_str(num, hexStr.c_str(), 16);
    mpz_mod(num, num, params.pairing->r);
    element_set_mpz(result, num);
    mpz_clear(num);
}

// Verilen stringleri birleştirip, Zₚ elemanı olarak hash'ler.
void hashVectorToZr(const std::vector<std::string> &data, TIACParams &params, element_t result) {
    std::stringstream ss;
    for (const auto &s : data)
        ss << s;
    hashStringToZr(ss.str(), params, result);
}

// HashToG1: Verilen stringi hash'leyip, g1 üzerinden G₁ elemanı üretir.
void hashToG1(const std::string &input, TIACParams &params, element_t output) {
    element_t hashZr;
    element_init_Zr(hashZr, params.pairing);
    hashStringToZr(input, params, hashZr);
    element_init_G1(output, params.pairing);
    element_pow_zn(output, params.g1, hashZr);
    element_clear(hashZr);
}

// --- CheckKoR Fonksiyonu (Algoritma 6) ---
// Girdi: params, com, comi, h, πs  
// İşlemler:
// 1. com''_i = g1^(s1) · h1^(s2) · comi^(c)
// 2. com'' = g1^(s3) · h^(s2) · com^(c)
// 3. c' = Hash(g1, h, h1, com, com'', comi, com''_i)
// 4. Eğer c' == c, ispat başarılı.
bool checkKoR(TIACParams &params, element_t com, element_t comi, element_t h, Proof &pi_s) {
    element_t comp_i, comp;
    element_init_G1(comp_i, params.pairing);
    element_init_G1(comp, params.pairing);
    
    { // Hesapla: comp_i = g1^(s1) * h1^(s2) * comi^(c)
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
    
    { // Hesapla: comp = g1^(s3) * h^(s2) * com^(c)
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
    
    // Hash verilerini hazırla
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

// --- blindSign Fonksiyonu (Algoritma 12) ---
// Girdi: prepared blind sign output (blindOut), voterin secret değerleri xm, ym  
// İşlemler:
// 1. Eğer CheckKoR(…) başarısızsa veya Hash(comi) != h ise hata döndür.
// 2. Aksi halde, cm = h^(xm) · g1^(ym) hesapla ve σ'_m = (h, cm) döndür.
BlindSignature blindSign(TIACParams &params, BlindSignOutput &blindOut, element_t xm, element_t ym) {
    BlindSignature sig;
    
    // Check: Recompute h' = Hash(comi) (yani h' = HashToG1(comi))
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
        std::cerr << "Blind Sign Check Failed: Either KoR proof is invalid or Hash(comi) != h." << std::endl;
        // Hata durumunda, sig.h ve sig.cm'yi sıfır olarak ayarlayalım.
        element_init_G1(sig.h, params.pairing);
        element_set0(sig.h);
        element_init_G1(sig.cm, params.pairing);
        element_set0(sig.cm);
        return sig;
    }
    
    // Eğer kontrol başarılıysa, hesapla: cm = h^(xm) * g1^(ym)
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
        element_clear(t1); element_clear(t2);
    }
    
    return sig;
}
