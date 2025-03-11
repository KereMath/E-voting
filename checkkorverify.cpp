#include "checkkorverify.h"
#include <sstream>
#include <iostream>
#include <vector>
#include <openssl/sha.h>
#include <cstring>
#include <iomanip>

// Bir element kopyalamak için yardımcı fonksiyon
// Bu, const giriş parametreleriyle çalışabilir
static inline void element_set_safe(element_t dest, const element_t src) {
    element_t src_copy;
    // Önce aynı türde bir element ile başlat
    element_init_same_as(src_copy, dest);
    // Kaynak elementin adresini kullanarak eleman eleman kopyala
    const element_s* src_elem = &src[0];
    element_s* src_copy_elem = &src_copy[0];
    *src_copy_elem = *const_cast<element_s*>(src_elem);
    // Şimdi dest'e kopyalayabiliriz
    element_set(dest, src_copy);
    element_clear(src_copy);
}

// String formundan element oluşturmak için yardımcı fonksiyon
static inline bool element_set_from_mpz_str(element_t elem, const char* str, int base, const mpz_t prime_order) {
    mpz_t m;
    mpz_init(m);
    if (mpz_set_str(m, str, base) != 0) {
        mpz_clear(m);
        return false;
    }
    // prime_order modülünde çalış
    mpz_mod(m, m, prime_order);
    element_set_mpz(elem, m);
    mpz_clear(m);
    return true;
}

// Use the same function as in the rest of the code to maintain consistency
std::string elementToStringG1(const element_t elem) {
    // Create a copy to work with
    element_t elem_copy;
    element_init_same_as(elem_copy, elem);
    element_set_safe(elem_copy, elem);
    
    int len = element_length_in_bytes(elem_copy);
    std::vector<unsigned char> buf(len);
    element_to_bytes(buf.data(), elem_copy);

    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (unsigned char c : buf) {
        oss << std::setw(2) << (int)c;
    }
    
    element_clear(elem_copy);
    return oss.str();
}

// New function for G2 elements
static std::string elementToStringG2(const element_t elem) {
    // Create a copy to work with
    element_t elem_copy;
    element_init_same_as(elem_copy, elem);
    element_set_safe(elem_copy, elem);
    
    int len = element_length_in_bytes(elem_copy);
    std::vector<unsigned char> buf(len);
    element_to_bytes(buf.data(), elem_copy);

    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (unsigned char c : buf) {
        oss << std::setw(2) << (int)c;
    }
    
    element_clear(elem_copy);
    return oss.str();
}

// Helper to print element for debugging
void debugPrintElement(const char* label, const element_t elem) {
    char buf[1024];
    element_snprintf(buf, sizeof(buf), "%B", elem);
    std::cout << "[KoR-DEBUG] " << label << " = " << buf << std::endl;
}

// Parse KoR proof tuple from string
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
    
    // Initialize elements
    element_init_Zr(c, pairing);
    element_init_Zr(s1, pairing);
    element_init_Zr(s2, pairing);
    element_init_Zr(s3, pairing);
    
    // Parse hex strings to elements
    if (!element_set_from_mpz_str(c, c_str.c_str(), 16, prime_order) ||
        !element_set_from_mpz_str(s1, s1_str.c_str(), 16, prime_order) ||
        !element_set_from_mpz_str(s2, s2_str.c_str(), 16, prime_order) ||
        !element_set_from_mpz_str(s3, s3_str.c_str(), 16, prime_order)) {
        
        std::cerr << "Error converting hex strings to elements" << std::endl;
        element_clear(c);
        element_clear(s1);
        element_clear(s2);
        element_clear(s3);
        return false;
    }
    
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
    
    // Debug print input parameters
    debugPrintElement("params.g1", params.g1);
    debugPrintElement("params.g2", params.g2);
    debugPrintElement("params.h1", params.h1);
    debugPrintElement("mvk.alpha2", mvk.alpha2);
    debugPrintElement("mvk.beta2", mvk.beta2);
    debugPrintElement("proveOutput.k", proveOutput.k);
    std::cout << "[KoR-DEBUG] comStr = " << comStr << std::endl;
    std::cout << "[KoR-DEBUG] proof_v = " << proveOutput.proof_v << std::endl;
    
    // Parse the commitment
    element_t com;
    element_init_G1(com, params.pairing);
    
    // comStr'dan bytes array oluştur ve element'e dönüştür
    std::vector<unsigned char> bin_data(comStr.length() / 2);
    for (size_t i = 0; i < comStr.length() / 2; i++) {
        std::string byteString = comStr.substr(i * 2, 2);
        bin_data[i] = (unsigned char)strtol(byteString.c_str(), NULL, 16);
    }
    element_from_bytes(com, bin_data.data());
    
    debugPrintElement("com (parsed)", com);
    
    // SEÇENEK 1: proof_v string'ini parse et (en güvenli yaklaşım)
    element_t c_parsed, s1_parsed, s2_parsed, s3_parsed;
    if (!parseKoRProof(proveOutput.proof_v, c_parsed, s1_parsed, s2_parsed, s3_parsed, 
                       params.pairing, params.prime_order)) {
        std::cerr << "[KoR-VERIFY] Failed to parse KoR proof!" << std::endl;
        element_clear(com);
        return false;
    }
    
    // Debug çıktısı
    debugPrintElement("c_parsed", c_parsed);
    debugPrintElement("s1_parsed", s1_parsed);
    debugPrintElement("s2_parsed", s2_parsed);
    debugPrintElement("s3_parsed", s3_parsed);
    
    // Calculate 1-c
    element_t one_minus_c;
    element_init_Zr(one_minus_c, params.pairing);
    element_set1(one_minus_c);
    element_sub(one_minus_c, one_minus_c, c_parsed);
    debugPrintElement("one_minus_c (1-c)", one_minus_c);
    
    // Calculate k_prime_prime = g2^(s1) * alpha2^(1-c) * beta2^s2
    element_t k_prime_prime;
    element_init_G2(k_prime_prime, params.pairing);
    
    // g2^(s1)
    element_t g2_s1;
    element_init_G2(g2_s1, params.pairing);
    element_pow_zn(g2_s1, params.g2, s1_parsed);
    debugPrintElement("g2_s1 (g2^s1)", g2_s1);
    
    // alpha2^(1-c)
    element_t alpha2_pow;
    element_init_G2(alpha2_pow, params.pairing);
    element_pow_zn(alpha2_pow, mvk.alpha2, one_minus_c);
    debugPrintElement("alpha2_pow (alpha2^(1-c))", alpha2_pow);
    
    // beta2^s2
    element_t beta2_s2;
    element_init_G2(beta2_s2, params.pairing);
    element_pow_zn(beta2_s2, mvk.beta2, s2_parsed);
    debugPrintElement("beta2_s2 (beta2^s2)", beta2_s2);
    
    // k_prime_prime = g2^s1 * alpha2^(1-c) * beta2^s2
    element_mul(k_prime_prime, g2_s1, alpha2_pow);
    debugPrintElement("k_prime_prime (after g2_s1 * alpha2_pow)", k_prime_prime);
    element_mul(k_prime_prime, k_prime_prime, beta2_s2);
    debugPrintElement("k_prime_prime (final)", k_prime_prime);
    
    // Calculate com_prime_prime = g1^s3 * h^s2 * com^c
    element_t com_prime_prime;
    element_init_G1(com_prime_prime, params.pairing);
    
    // g1^s3
    element_t g1_s3;
    element_init_G1(g1_s3, params.pairing);
    element_pow_zn(g1_s3, params.g1, s3_parsed);
    debugPrintElement("g1_s3 (g1^s3)", g1_s3);
    
    // h^s2 - Using aggSig_h instead of params.h1
    element_t h_s2;
    element_init_G1(h_s2, params.pairing);
    element_pow_zn(h_s2, aggSig_h, s2_parsed);
    debugPrintElement("h_s2 (h^s2)", h_s2);
    
    // com^c
    element_t com_c;
    element_init_G1(com_c, params.pairing);
    element_pow_zn(com_c, com, c_parsed);
    debugPrintElement("com_c (com^c)", com_c);
    
    // Multiply all components
    element_mul(com_prime_prime, g1_s3, h_s2);
    debugPrintElement("com_prime_prime (after g1_s3 * h_s2)", com_prime_prime);
    element_mul(com_prime_prime, com_prime_prime, com_c);
    debugPrintElement("com_prime_prime (final)", com_prime_prime);
    
    // Compute c_prime using the same hash function as in proveCredential.cpp
    element_t c_prime;
    element_init_Zr(c_prime, params.pairing);

    // Exact same hash computation as in proveCredential.cpp
    std::ostringstream hashOSS;
    hashOSS << elementToStringG1(params.g1)
            << elementToStringG2(params.g2)
            << elementToStringG1(aggSig_h)  // ÖNEMLİ: aggSig_h kullanıyoruz
            << elementToStringG1(com)
            << elementToStringG1(com_prime_prime)
            << elementToStringG2(proveOutput.k)
            << elementToStringG2(k_prime_prime);

    std::string hashInput = hashOSS.str();
    std::cout << "[KoR-DEBUG] Hash input (hex, truncated): " << hashInput.substr(0, 64) << "..." << std::endl;

    unsigned char hashDigest[SHA512_DIGEST_LENGTH];
    SHA512(reinterpret_cast<const unsigned char*>(hashInput.data()), hashInput.size(), hashDigest);

    std::ostringstream hashFinalOSS;
    hashFinalOSS << std::hex << std::setfill('0');
    for (int i = 0; i < SHA512_DIGEST_LENGTH; i++) {
        hashFinalOSS << std::setw(2) << (int)hashDigest[i];
    }
    std::string c_prime_str = hashFinalOSS.str();
    std::cout << "[KoR-DEBUG] Hash output (hex, truncated): " << c_prime_str.substr(0, 64) << "..." << std::endl;

    // Convert hash to element in Zp
    mpz_t c_prime_mpz;
    mpz_init(c_prime_mpz);
    if(mpz_set_str(c_prime_mpz, c_prime_str.c_str(), 16) != 0) {
        std::cerr << "[KoR-VERIFY] Error converting hash to mpz" << std::endl;
        mpz_clear(c_prime_mpz);
        // Cleanup
        element_clear(c_prime);
        element_clear(com);
        element_clear(c_parsed);
        element_clear(s1_parsed);
        element_clear(s2_parsed);
        element_clear(s3_parsed);
        element_clear(one_minus_c);
        element_clear(k_prime_prime);
        element_clear(g2_s1);
        element_clear(alpha2_pow);
        element_clear(beta2_s2);
        element_clear(com_prime_prime);
        element_clear(g1_s3);
        element_clear(h_s2);
        element_clear(com_c);
        return false;
    }

    // Debug çıktısı
    char* mpz_hex = mpz_get_str(nullptr, 16, c_prime_mpz);
    std::cout << "[KoR-DEBUG] c_prime_mpz (hex, truncated): " << std::string(mpz_hex).substr(0, 64) << "..." << std::endl;
    free(mpz_hex);

    mpz_mod(c_prime_mpz, c_prime_mpz, params.prime_order);
    mpz_hex = mpz_get_str(nullptr, 16, c_prime_mpz);
    std::cout << "[KoR-DEBUG] c_prime_mpz after mod (hex): " << mpz_hex << std::endl;
    free(mpz_hex);

    element_set_mpz(c_prime, c_prime_mpz);
    mpz_clear(c_prime_mpz);
    debugPrintElement("c_prime (final)", c_prime);
    
    // Check if c_prime == c_parsed
    bool result = (element_cmp(c_prime, c_parsed) == 0);
    
    // Debug output
    debugPrintElement("c_parsed", c_parsed);
    debugPrintElement("c_prime", c_prime);
    std::cout << "[KoR-VERIFY] Result = " << (result ? "PASSED" : "FAILED") << std::endl;
    
    // Clean up
    element_clear(c_parsed);
    element_clear(s1_parsed);
    element_clear(s2_parsed);
    element_clear(s3_parsed);
    element_clear(com);
    element_clear(one_minus_c);
    element_clear(k_prime_prime);
    element_clear(g2_s1);
    element_clear(alpha2_pow);
    element_clear(beta2_s2);
    element_clear(com_prime_prime);
    element_clear(g1_s3);
    element_clear(h_s2);
    element_clear(com_c);
    element_clear(c_prime);
    
    return result;
}