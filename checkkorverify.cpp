#include "checkkorverify.h"
#include <sstream>
#include <iostream>
#include <vector>
#include <openssl/sha.h>
#include <cstring>
#include <iomanip>

// PBC kütüphanesindeki const element problemini çözmek için
// const element'ten non-const kopya oluşturan yardımcı fonksiyon
static void create_element_copy(element_t dest, const element_t src, pairing_t pairing) {
    // src'ın türüne göre dest'i doğru tipte başlat
    if (element_is_in_G1(const_cast<element_t>(src))) {
        element_init_G1(dest, pairing);
    } else if (element_is_in_G2(const_cast<element_t>(src))) {
        element_init_G2(dest, pairing);
    } else {
        element_init_Zr(dest, pairing);
    }
    
    // src'ın bytes temsilini al ve dest'e kopyala
    int len = element_length_in_bytes(const_cast<element_t>(src));
    unsigned char* buf = new unsigned char[len];
    element_to_bytes(buf, const_cast<element_t>(src));
    element_from_bytes(dest, buf);
    delete[] buf;
}

// Hex string'i byte dizisine dönüştüren yardımcı fonksiyon
static std::vector<unsigned char> hex_to_bytes(const std::string& hex) {
    std::vector<unsigned char> bytes;
    for (size_t i = 0; i < hex.length(); i += 2) {
        std::string byteString = hex.substr(i, 2);
        unsigned char byte = (unsigned char)strtol(byteString.c_str(), NULL, 16);
        bytes.push_back(byte);
    }
    return bytes;
}

// Element'i hex string'e dönüştürme fonksiyonu (G1 veya G2 için)
static std::string element_to_hex_string(const element_t elem) {
    int len = element_length_in_bytes(const_cast<element_t>(elem));
    unsigned char* buf = new unsigned char[len];
    element_to_bytes(buf, const_cast<element_t>(elem));
    
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (int i = 0; i < len; i++) {
        oss << std::setw(2) << (int)buf[i];
    }
    
    delete[] buf;
    return oss.str();
}

// Debug için element yazdırma fonksiyonu
static void debug_print_element(const char* label, const element_t elem) {
    char buf[1024];
    element_snprintf(buf, sizeof(buf), "%B", const_cast<element_t>(elem));
    std::cout << "[KoR-DEBUG] " << label << " = " << buf << std::endl;
}

// KoR proof_v string'ini parse eden fonksiyon
bool parseKoRProof(
    const std::string &proof_v, 
    element_t c, 
    element_t s1, 
    element_t s2, 
    element_t s3, 
    pairing_t pairing,
    const mpz_t prime_order
) {
    std::istringstream iss(proof_v);
    std::string c_str, s1_str, s2_str, s3_str;
    
    if (!(iss >> c_str >> s1_str >> s2_str >> s3_str)) {
        std::cerr << "Error parsing KoR tuple: " << proof_v << std::endl;
        return false;
    }
    
    // Zr elemanları olarak başlat
    element_init_Zr(c, pairing);
    element_init_Zr(s1, pairing);
    element_init_Zr(s2, pairing);
    element_init_Zr(s3, pairing);
    
    // Hex string'leri mpz_t'ye, sonra element'e dönüştür
    mpz_t temp;
    mpz_init(temp);
    
    // c değeri
    if (mpz_set_str(temp, c_str.c_str(), 16) != 0) {
        mpz_clear(temp);
        return false;
    }
    mpz_mod(temp, temp, prime_order);  // prime_order modülünde
    element_set_mpz(c, temp);
    
    // s1 değeri
    if (mpz_set_str(temp, s1_str.c_str(), 16) != 0) {
        mpz_clear(temp);
        return false;
    }
    mpz_mod(temp, temp, prime_order);
    element_set_mpz(s1, temp);
    
    // s2 değeri
    if (mpz_set_str(temp, s2_str.c_str(), 16) != 0) {
        mpz_clear(temp);
        return false;
    }
    mpz_mod(temp, temp, prime_order);
    element_set_mpz(s2, temp);
    
    // s3 değeri
    if (mpz_set_str(temp, s3_str.c_str(), 16) != 0) {
        mpz_clear(temp);
        return false;
    }
    mpz_mod(temp, temp, prime_order);
    element_set_mpz(s3, temp);
    
    mpz_clear(temp);
    return true;
}

bool checkKoRVerify(
    TIACParams &params,
    const ProveCredentialOutput &proveOutput,
    const MasterVerKey &mvk,
    const std::string &comStr,
    const element_t aggSig_h
) {
    std::cout << "[KoR-VERIFY] Starting Knowledge of Representation verification..." << std::endl;
    
    // Debug bilgileri
    debug_print_element("params.g1", params.g1);
    debug_print_element("params.g2", params.g2);
    debug_print_element("params.h1", params.h1);
    debug_print_element("mvk.alpha2", mvk.alpha2);
    debug_print_element("mvk.beta2", mvk.beta2);
    debug_print_element("proveOutput.k", proveOutput.k);
    std::cout << "[KoR-DEBUG] comStr = " << comStr << std::endl;
    std::cout << "[KoR-DEBUG] proof_v = " << proveOutput.proof_v << std::endl;
    
    // Commitment'ı parse et
    element_t com;
    element_init_G1(com, params.pairing);
    
    std::vector<unsigned char> com_bytes = hex_to_bytes(comStr);
    element_from_bytes(com, com_bytes.data());
    debug_print_element("com (parsed)", com);
    
    // KoR proof elementlerini parse et (en güvenli yöntem)
    element_t c_parsed, s1_parsed, s2_parsed, s3_parsed;
    if (!parseKoRProof(proveOutput.proof_v, c_parsed, s1_parsed, s2_parsed, s3_parsed,
                      params.pairing, params.prime_order)) {
        std::cerr << "[KoR-VERIFY] Failed to parse KoR proof!" << std::endl;
        element_clear(com);
        return false;
    }
    
    debug_print_element("c_parsed", c_parsed);
    debug_print_element("s1_parsed", s1_parsed);
    debug_print_element("s2_parsed", s2_parsed);
    debug_print_element("s3_parsed", s3_parsed);
    
    // 1-c hesapla
    element_t one_minus_c;
    element_init_Zr(one_minus_c, params.pairing);
    element_set1(one_minus_c);
    element_sub(one_minus_c, one_minus_c, c_parsed);
    debug_print_element("one_minus_c (1-c)", one_minus_c);
    
    // Const elemantları kopyala (mvk ve aggSig_h)
    element_t alpha2_copy, beta2_copy, aggSig_h_copy;
    create_element_copy(alpha2_copy, mvk.alpha2, params.pairing);
    create_element_copy(beta2_copy, mvk.beta2, params.pairing);
    create_element_copy(aggSig_h_copy, aggSig_h, params.pairing);
    
    // k_prime_prime = g2^(s1) * alpha2^(1-c) * beta2^s2
    element_t k_prime_prime;
    element_init_G2(k_prime_prime, params.pairing);
    
    // g2^(s1)
    element_t g2_s1;
    element_init_G2(g2_s1, params.pairing);
    element_pow_zn(g2_s1, params.g2, s1_parsed);
    debug_print_element("g2_s1 (g2^s1)", g2_s1);
    
    // alpha2^(1-c)
    element_t alpha2_pow;
    element_init_G2(alpha2_pow, params.pairing);
    element_pow_zn(alpha2_pow, alpha2_copy, one_minus_c);
    debug_print_element("alpha2_pow (alpha2^(1-c))", alpha2_pow);
    
    // beta2^s2
    element_t beta2_s2;
    element_init_G2(beta2_s2, params.pairing);
    element_pow_zn(beta2_s2, beta2_copy, s2_parsed);
    debug_print_element("beta2_s2 (beta2^s2)", beta2_s2);
    
    // k_prime_prime = g2^s1 * alpha2^(1-c) * beta2^s2
    element_mul(k_prime_prime, g2_s1, alpha2_pow);
    debug_print_element("k_prime_prime (after g2_s1 * alpha2_pow)", k_prime_prime);
    element_mul(k_prime_prime, k_prime_prime, beta2_s2);
    debug_print_element("k_prime_prime (final)", k_prime_prime);
    
    // com_prime_prime = g1^s3 * h^s2 * com^c
    element_t com_prime_prime;
    element_init_G1(com_prime_prime, params.pairing);
    
    // g1^s3
    element_t g1_s3;
    element_init_G1(g1_s3, params.pairing);
    element_pow_zn(g1_s3, params.g1, s3_parsed);
    debug_print_element("g1_s3 (g1^s3)", g1_s3);
    
    // h^s2 - Using aggSig_h_copy instead of aggSig_h
    element_t h_s2;
    element_init_G1(h_s2, params.pairing);
    element_pow_zn(h_s2, aggSig_h_copy, s2_parsed);
    debug_print_element("h_s2 (h^s2)", h_s2);
    
    // com^c
    element_t com_c;
    element_init_G1(com_c, params.pairing);
    element_pow_zn(com_c, com, c_parsed);
    debug_print_element("com_c (com^c)", com_c);
    
    // Multiply all components
    element_mul(com_prime_prime, g1_s3, h_s2);
    debug_print_element("com_prime_prime (after g1_s3 * h_s2)", com_prime_prime);
    element_mul(com_prime_prime, com_prime_prime, com_c);
    debug_print_element("com_prime_prime (final)", com_prime_prime);
    
    // proveOutput.k'nın non-const kopyasını oluştur
    element_t k_copy;
    create_element_copy(k_copy, proveOutput.k, params.pairing);
    
    // Hash hesapla
    std::ostringstream hashOSS;
    hashOSS << element_to_hex_string(params.g1)
            << element_to_hex_string(params.g2)
            << element_to_hex_string(aggSig_h_copy)
            << element_to_hex_string(com)
            << element_to_hex_string(com_prime_prime)
            << element_to_hex_string(k_copy)
            << element_to_hex_string(k_prime_prime);
    
    std::string hashInput = hashOSS.str();
    std::cout << "[KoR-DEBUG] Hash input (hex, truncated): " << hashInput.substr(0, 64) << "..." << std::endl;
    
    // SHA-512 hash
    unsigned char hashDigest[SHA512_DIGEST_LENGTH];
    SHA512(reinterpret_cast<const unsigned char*>(hashInput.data()), hashInput.size(), hashDigest);
    
    std::ostringstream hashOutputOSS;
    hashOutputOSS << std::hex << std::setfill('0');
    for (int i = 0; i < SHA512_DIGEST_LENGTH; i++) {
        hashOutputOSS << std::setw(2) << (int)hashDigest[i];
    }
    std::string hashOutput = hashOutputOSS.str();
    std::cout << "[KoR-DEBUG] Hash output (hex, truncated): " << hashOutput.substr(0, 64) << "..." << std::endl;
    
    // Hash değerini Zr elemanına dönüştür
    mpz_t c_prime_mpz;
    mpz_init(c_prime_mpz);
    if (mpz_set_str(c_prime_mpz, hashOutput.c_str(), 16) != 0) {
        std::cerr << "[KoR-VERIFY] Error converting hash to mpz" << std::endl;
        mpz_clear(c_prime_mpz);
        // Cleanup
        element_clear(c_parsed);
        element_clear(s1_parsed);
        element_clear(s2_parsed);
        element_clear(s3_parsed);
        element_clear(com);
        element_clear(one_minus_c);
        element_clear(k_prime_prime);
        element_clear(g2_s1);
        element_clear(alpha2_copy);
        element_clear(alpha2_pow);
        element_clear(beta2_copy);
        element_clear(beta2_s2);
        element_clear(aggSig_h_copy);
        element_clear(k_copy);
        element_clear(com_prime_prime);
        element_clear(g1_s3);
        element_clear(h_s2);
        element_clear(com_c);
        return false;
    }
    
    // Debug
    char* mpz_hex = mpz_get_str(nullptr, 16, c_prime_mpz);
    std::cout << "[KoR-DEBUG] c_prime_mpz (hex, truncated): " << std::string(mpz_hex).substr(0, 64) << "..." << std::endl;
    free(mpz_hex);
    
    // prime_order modülünde hesapla
    mpz_mod(c_prime_mpz, c_prime_mpz, params.prime_order);
    mpz_hex = mpz_get_str(nullptr, 16, c_prime_mpz);
    std::cout << "[KoR-DEBUG] c_prime_mpz after mod (hex): " << mpz_hex << std::endl;
    free(mpz_hex);
    
    // c_prime oluştur
    element_t c_prime;
    element_init_Zr(c_prime, params.pairing);
    element_set_mpz(c_prime, c_prime_mpz);
    mpz_clear(c_prime_mpz);
    debug_print_element("c_prime (final)", c_prime);
    
    // c_prime ile c_parsed aynı mı kontrol et
    bool result = (element_cmp(c_prime, c_parsed) == 0);
    
    // Debug çıktıları
    char c_buf[1024], c_prime_buf[1024];
    element_snprintf(c_buf, sizeof(c_buf), "%B", c_parsed);
    element_snprintf(c_prime_buf, sizeof(c_prime_buf), "%B", c_prime);
    std::cout << "[KoR-VERIFY] c      = " << c_buf << std::endl;
    std::cout << "[KoR-VERIFY] c'     = " << c_prime_buf << std::endl;
    std::cout << "[KoR-VERIFY] Result = " << (result ? "PASSED" : "FAILED") << std::endl;
    
    // Cleanup
    element_clear(c_parsed);
    element_clear(s1_parsed);
    element_clear(s2_parsed);
    element_clear(s3_parsed);
    element_clear(com);
    element_clear(one_minus_c);
    element_clear(k_prime_prime);
    element_clear(g2_s1);
    element_clear(alpha2_copy);
    element_clear(alpha2_pow);
    element_clear(beta2_copy);
    element_clear(beta2_s2);
    element_clear(aggSig_h_copy);
    element_clear(k_copy);
    element_clear(com_prime_prime);
    element_clear(g1_s3);
    element_clear(h_s2);
    element_clear(com_c);
    element_clear(c_prime);
    
    return result;
}