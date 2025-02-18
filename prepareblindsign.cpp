#include "prepareblindsign.h"
#include <pbc/pbc.h>
#include <gmp.h>
#include <openssl/sha.h>
#include <sstream>
#include <iomanip>
#include <string>
#include <vector>
#include <iostream>

// --- Yardımcı fonksiyonlar ---

// Verilen stringi SHA-512 ile hash'ler, hex formatında döndürür.
std::string sha512Hex(const std::string &input) {
    unsigned char hash[SHA512_DIGEST_LENGTH];
    SHA512(reinterpret_cast<const unsigned char*>(input.c_str()), input.size(), hash);
    std::stringstream ss;
    for (int i = 0; i < SHA512_DIGEST_LENGTH; i++) {
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
    }
    return ss.str();
}

// Yardımcı: Element'in string temsilini alır.
std::string elementToStr(element_t e) {
    char buffer[1024];
    element_snprintf(buffer, sizeof(buffer), "%B", e);
    return std::string(buffer);
}

// HashStringToZr: Verilen stringi SHA-512 ile hash'ler ve Zₚ elemanına dönüştürür.
void hashStringToZr(const std::string &input, TIACParams &params, element_t result) {
    std::string hexStr = sha512Hex(input);
    mpz_t num;
    mpz_init(num);
    mpz_set_str(num, hexStr.c_str(), 16);
    mpz_mod(num, num, params.pairing->r);
    element_set_mpz(result, num);
    mpz_clear(num);
}

// Hash a vector of strings to a Zₚ element.
void hashVectorToZr(const std::vector<std::string> &data, TIACParams &params, element_t result) {
    std::stringstream ss;
    for (const auto &s : data)
        ss << s;
    hashStringToZr(ss.str(), params, result);
}

// HashToG1: Hash'leyip Zₚ elemanından G₁ elemanı üretir: h = g1^(hashZr)
void hashToG1(TIACParams &params, element_t input, element_t output) {
    element_t hashZr;
    element_init_Zr(hashZr, params.pairing);
    std::string inStr = elementToStr(input);
    hashStringToZr(inStr, params, hashZr);
    element_init_G1(output, params.pairing);
    element_pow_zn(output, params.g1, hashZr);
    element_clear(hashZr);
}

// --- prepareBlindSign fonksiyonu ---
// Girdi: params, realID (11 haneli sayısal string)
// Çıktı: BlindSignOutput (com, comi, h, πs)
BlindSignOutput prepareBlindSign(TIACParams &params, const std::string &realID) {
    BlindSignOutput out;
    
    // Önce, realID'yi Zₚ elemanına çevir (DID_elem)
    element_t DID_elem;
    element_init_Zr(DID_elem, params.pairing);
    mpz_t id_mpz;
    mpz_init(id_mpz);
    if(mpz_set_str(id_mpz, realID.c_str(), 10) != 0) {
        std::cerr << "Error: realID sayisal degil!" << std::endl;
    }
    element_set_mpz(DID_elem, id_mpz);
    mpz_clear(id_mpz);
    
    // Adım 1: Rastgele oᵢ ∈ Zₚ seç
    element_t o_i;
    element_init_Zr(o_i, params.pairing);
    element_random(o_i);
    
    // Adım 2: comᵢ ← g1^(oᵢ) · h1^(DID_elem)
    element_init_G1(out.comi, params.pairing);
    {
        element_t temp1, temp2;
        element_init_G1(temp1, params.pairing);
        element_init_G1(temp2, params.pairing);
        element_pow_zn(temp1, params.g1, o_i);
        element_pow_zn(temp2, params.h1, DID_elem);
        element_mul(out.comi, temp1, temp2);
        element_clear(temp1);
        element_clear(temp2);
    }
    
    // Adım 3: h ← Hash(comᵢ) (h ∈ G₁)
    hashToG1(params, out.comi, out.h);
    
    // Adım 4: Rastgele o ∈ Zₚ seç
    element_t o;
    element_init_Zr(o, params.pairing);
    element_random(o);
    
    // Adım 5: com ← g1^(o) · h^(DID_elem)
    element_init_G1(out.com, params.pairing);
    {
        element_t temp1, temp2;
        element_init_G1(temp1, params.pairing);
        element_init_G1(temp2, params.pairing);
        element_pow_zn(temp1, params.g1, o);
        element_pow_zn(temp2, out.h, DID_elem);
        element_mul(out.com, temp1, temp2);
        element_clear(temp1);
        element_clear(temp2);
    }
    
    // Adım 6: KoR (Algorithm 5) ile πs hesaplanması
    // Algoritma 5:
    // (a) Rastgele r1, r2, r3 ∈ Zₚ seç
    element_t r1, r2, r3;
    element_init_Zr(r1, params.pairing); element_random(r1);
    element_init_Zr(r2, params.pairing); element_random(r2);
    element_init_Zr(r3, params.pairing); element_random(r3);
    
    // (b) com′ᵢ ← g1^(r1) · h1^(r2)
    element_t comp_i;
    element_init_G1(comp_i, params.pairing);
    {
        element_t t1, t2;
        element_init_G1(t1, params.pairing);
        element_init_G1(t2, params.pairing);
        element_pow_zn(t1, params.g1, r1);
        element_pow_zn(t2, params.h1, r2);
        element_mul(comp_i, t1, t2);
        element_clear(t1); element_clear(t2);
    }
    
    // (c) com′ ← g1^(r3) · h^(r2)
    element_t comp;
    element_init_G1(comp, params.pairing);
    {
        element_t t1, t2;
        element_init_G1(t1, params.pairing);
        element_init_G1(t2, params.pairing);
        element_pow_zn(t1, params.g1, r3);
        element_pow_zn(t2, out.h, r2);
        element_mul(comp, t1, t2);
        element_clear(t1); element_clear(t2);
    }
    
    // (d) c ← Hash(g1, h, h1, com, com′, comᵢ, com′ᵢ) ∈ Zₚ
    std::vector<std::string> hashData;
    hashData.push_back(elementToStr(params.g1));
    hashData.push_back(elementToStr(out.h));
    hashData.push_back(elementToStr(params.h1));
    hashData.push_back(elementToStr(out.com));
    hashData.push_back(elementToStr(comp));
    hashData.push_back(elementToStr(out.comi));
    hashData.push_back(elementToStr(comp_i));
    element_init_Zr(out.pi_s.c, params.pairing);
    hashVectorToZr(hashData, params, out.pi_s.c);
    
    // (e) s1 ← r1 − c · oᵢ, s2 ← r2 − c · DID_elem, s3 ← r3 − c · o
    element_t tempZr;
    element_init_Zr(tempZr, params.pairing);
    
    element_init_Zr(out.pi_s.s1, params.pairing);
    element_mul(tempZr, out.pi_s.c, o_i);
    element_sub(out.pi_s.s1, r1, tempZr);
    
    element_init_Zr(out.pi_s.s2, params.pairing);
    element_mul(tempZr, out.pi_s.c, DID_elem);
    element_sub(out.pi_s.s2, r2, tempZr);
    
    element_init_Zr(out.pi_s.s3, params.pairing);
    element_mul(tempZr, out.pi_s.c, o);
    element_sub(out.pi_s.s3, r3, tempZr);
    
    element_clear(tempZr);
    
    // (f) Temizlik: r1, r2, r3, comp, comp_i, oᵢ, o, DID_elem
    element_clear(r1);
    element_clear(r2);
    element_clear(r3);
    element_clear(comp);
    element_clear(comp_i);
    element_clear(o_i);
    element_clear(o);
    element_clear(DID_elem);
    
    return out;
}
