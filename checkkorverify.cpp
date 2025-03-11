#include "checkkorverify.h"
#include <sstream>
#include <iostream>
#include <vector>
#include <openssl/sha.h>
#include <cstring>
#include <iomanip>

// Helper: const element_s*'yi non-const element_s*'ye dönüştürür.
static inline element_s* toNonConst(const element_s* in) {
    return const_cast<element_s*>(in);
}

// Use the same function as in the rest of the code to maintain consistency
std::string elementToStringG1(const element_t elem) {
    // Use toNonConst to handle the const parameter
    element_t elem_nonconst;
    elem_nonconst[0] = *toNonConst(&elem[0]);
    
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

// New function for G2 elements
static std::string elementToStringG2(const element_t elem) {
    // Use toNonConst to handle the const parameter
    element_t elem_nonconst;
    elem_nonconst[0] = *toNonConst(&elem[0]);
    
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

// Helper function to convert hex string back to element
bool elementFromHexString(const std::string &hexStr, element_t result, pairing_t pairing, bool isZr = false) {
    try {
        if (isZr) {
            element_init_Zr(result, pairing);
        } else {
            element_init_G1(result, pairing);
        }
        
        // Convert hex string to bytes
        std::vector<unsigned char> bytes;
        for (size_t i = 0; i < hexStr.length(); i += 2) {
            std::string byteString = hexStr.substr(i, 2);
            unsigned char byte = (unsigned char)strtol(byteString.c_str(), NULL, 16);
            bytes.push_back(byte);
        }
        
        // Set the element from bytes
        element_from_bytes(result, bytes.data());
        return true;
    } catch (...) {
        std::cerr << "Error converting hex string to element\n";
        return false;
    }
}

// Helper to print element for debugging
void debugPrintElement(const char* label, const element_t elem) {
    char buf[1024];
    element_snprintf(buf, sizeof(buf), "%B", elem);
    std::cout << "[KoR-DEBUG] " << label << " = " << buf << std::endl;
}

bool checkKoRVerify(
    TIACParams &params,
    const ProveCredentialOutput &proveOutput,
    const MasterVerKey &mvk,
    const std::string &comStr,
    const element_t aggSig_h  // New parameter for aggregate signature h
) {
    std::cout << "[KoR-VERIFY] Starting Knowledge of Representation verification..." << std::endl;
    
    // Debug print input parameters
    char buf[1024];
    element_snprintf(buf, sizeof(buf), "%B", params.g1);
    std::cout << "[KoR-DEBUG] params.g1 = " << buf << std::endl;
    element_snprintf(buf, sizeof(buf), "%B", params.g2);
    std::cout << "[KoR-DEBUG] params.g2 = " << buf << std::endl;
    element_snprintf(buf, sizeof(buf), "%B", params.h1);
    std::cout << "[KoR-DEBUG] params.h1 = " << buf << std::endl;
    element_snprintf(buf, sizeof(buf), "%B", mvk.alpha2);
    std::cout << "[KoR-DEBUG] mvk.alpha2 = " << buf << std::endl;
    element_snprintf(buf, sizeof(buf), "%B", mvk.beta2);
    std::cout << "[KoR-DEBUG] mvk.beta2 = " << buf << std::endl;
    element_snprintf(buf, sizeof(buf), "%B", proveOutput.k);
    std::cout << "[KoR-DEBUG] proveOutput.k = " << buf << std::endl;
    std::cout << "[KoR-DEBUG] comStr = " << comStr << std::endl;
    
    // Parse the commitment
    element_t com;
    element_init_G1(com, params.pairing);
    if (!elementFromHexString(comStr, com, params.pairing)) {
        std::cerr << "[KoR-VERIFY] Failed to parse commitment!" << std::endl;
        element_clear(com);
        return false;
    }
    debugPrintElement("com (parsed)", com);
    
    // Create non-const copies of the proof elements
    element_t c_copy, s1_copy, s2_copy, s3_copy;
    element_init_Zr(c_copy,  params.pairing);
    element_init_Zr(s1_copy, params.pairing);
    element_init_Zr(s2_copy, params.pairing);
    element_init_Zr(s3_copy, params.pairing);

    element_set(c_copy,  proveOutput.c);
    element_set(s1_copy, proveOutput.s1);
    element_set(s2_copy, proveOutput.s2);
    element_set(s3_copy, proveOutput.s3);

    // Debug print (isteğe bağlı)
    debugPrintElement("c_copy",  c_copy);
    debugPrintElement("s1_copy", s1_copy);
    debugPrintElement("s2_copy", s2_copy);
    debugPrintElement("s3_copy", s3_copy);
    
    // Debug print proof elements
    debugPrintElement("c_copy", c_copy);
    debugPrintElement("s1_copy", s1_copy);
    debugPrintElement("s2_copy", s2_copy);
    debugPrintElement("s3_copy", s3_copy);
    
    // Calculate 1-c
    element_t one_minus_c;
    element_init_Zr(one_minus_c, params.pairing);
    element_set1(one_minus_c);
    element_sub(one_minus_c, one_minus_c, c_copy);
    debugPrintElement("one_minus_c (1-c)", one_minus_c);
    
    // Calculate k_prime_prime = g2^(s1) * alpha2^(1-c) * k * beta2^s2
    element_t k_prime_prime;
    element_init_G2(k_prime_prime, params.pairing);
    
    // g2^(s1)
    element_t g2_s1;
    element_init_G2(g2_s1, params.pairing);
    element_pow_zn(g2_s1, params.g2, s1_copy);
    debugPrintElement("g2_s1 (g2^s1)", g2_s1);
    
    // alpha2^(1-c)
    element_t alpha2_pow, alpha2_copy;
    element_init_G2(alpha2_pow, params.pairing);
    element_init_G2(alpha2_copy, params.pairing);
    element_set(alpha2_copy, toNonConst(&mvk.alpha2[0]));
    element_pow_zn(alpha2_pow, alpha2_copy, one_minus_c);
    debugPrintElement("alpha2_copy", alpha2_copy);
    debugPrintElement("alpha2_pow (alpha2^(1-c))", alpha2_pow);
    
    // beta2^s2
    element_t beta2_s2, beta2_copy;
    element_init_G2(beta2_s2, params.pairing);
    element_init_G2(beta2_copy, params.pairing);
    element_set(beta2_copy, toNonConst(&mvk.beta2[0]));
    element_pow_zn(beta2_s2, beta2_copy, s2_copy);
    debugPrintElement("beta2_copy", beta2_copy);
    debugPrintElement("beta2_s2 (beta2^s2)", beta2_s2);
    
    // Create a copy of k for non-const use
    element_t k_copy;
    element_init_G2(k_copy, params.pairing);
    element_set(k_copy, toNonConst(&proveOutput.k[0]));
    debugPrintElement("k_copy", k_copy);
    
    // Multiply all components
    element_mul(k_prime_prime, g2_s1, alpha2_pow);
    debugPrintElement("k_prime_prime (after g2_s1 * alpha2_pow)", k_prime_prime);
    element_mul(k_prime_prime, k_prime_prime, k_copy);
    debugPrintElement("k_prime_prime (after * k_copy)", k_prime_prime);
    element_mul(k_prime_prime, k_prime_prime, beta2_s2);
    debugPrintElement("k_prime_prime (final)", k_prime_prime);
    
    // Calculate com_prime_prime = g1^s3 * h^s2 * com^c
    element_t com_prime_prime;
    element_init_G1(com_prime_prime, params.pairing);
    
    // g1^s3
    element_t g1_s3;
    element_init_G1(g1_s3, params.pairing);
    element_pow_zn(g1_s3, params.g1, s3_copy);
    debugPrintElement("g1_s3 (g1^s3)", g1_s3);
    
    // h^s2 - Using aggSig_h instead of params.h1
    element_t h_s2;
    element_init_G1(h_s2, params.pairing);
    element_pow_zn(h_s2, toNonConst(&aggSig_h[0]), s2_copy);  // Use toNonConst helper
    debugPrintElement("h_s2 (h^s2)", h_s2);
    
    // com^c
    element_t com_c;
    element_init_G1(com_c, params.pairing);
    element_pow_zn(com_c, com, c_copy);
    debugPrintElement("com_c (com^c)", com_c);
    
    // Multiply all components
    element_mul(com_prime_prime, g1_s3, h_s2);
    debugPrintElement("com_prime_prime (after g1_s3 * h_s2)", com_prime_prime);
    element_mul(com_prime_prime, com_prime_prime, com_c);
    debugPrintElement("com_prime_prime (final)", com_prime_prime);
    
    // Compute c_prime using the same hash function as in proveCredential.cpp
    element_t c_prime;
    element_init_Zr(c_prime, params.pairing);

    // Exact same hash computation as in proveCredential.cpp, but with G2 serialization
    std::ostringstream hashOSS;
    hashOSS << elementToStringG1(params.g1)
            << elementToStringG2(params.g2)   // Use G2 serialization
            << elementToStringG1(aggSig_h)    // Use aggSig_h instead of params.h1
            << elementToStringG1(com)
            << elementToStringG1(com_prime_prime)
            << elementToStringG2(k_copy)      // Use G2 serialization
            << elementToStringG2(k_prime_prime); // Use G2 serialization

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
        mpz_clear(c_prime_mpz);
        element_clear(c_prime);
        element_clear(com);
        element_clear(c_copy);
        element_clear(s1_copy);
        element_clear(s2_copy);
        element_clear(s3_copy);
        element_clear(one_minus_c);
        element_clear(k_prime_prime);
        element_clear(g2_s1);
        element_clear(alpha2_copy);
        element_clear(alpha2_pow);
        element_clear(beta2_copy);
        element_clear(beta2_s2);
        element_clear(k_copy);
        element_clear(com_prime_prime);
        element_clear(g1_s3);
        element_clear(h_s2);
        element_clear(com_c);
        throw std::runtime_error("checkKoRVerify: Error converting hash to mpz");
    }

    char mpz_buf[1024];
    mpz_get_str(mpz_buf, 16, c_prime_mpz);
    std::cout << "[KoR-DEBUG] c_prime_mpz (hex, truncated): " << std::string(mpz_buf).substr(0, 64) << "..." << std::endl;

    mpz_mod(c_prime_mpz, c_prime_mpz, params.prime_order);
    mpz_get_str(mpz_buf, 16, c_prime_mpz);
    std::cout << "[KoR-DEBUG] c_prime_mpz after mod (hex): " << mpz_buf << std::endl;

    element_set_mpz(c_prime, c_prime_mpz);
    mpz_clear(c_prime_mpz);
    debugPrintElement("c_prime (final)", c_prime);
    
    // Check if c_prime == c
    bool result = (element_cmp(c_prime, c_copy) == 0);
    
    // Debug output
    char c_buf[1024], c_prime_buf[1024];
    element_snprintf(c_buf, sizeof(c_buf), "%B", c_copy);
    element_snprintf(c_prime_buf, sizeof(c_prime_buf), "%B", c_prime);
    std::cout << "[KoR-VERIFY] c      = " << c_buf << std::endl;
    std::cout << "[KoR-VERIFY] c'     = " << c_prime_buf << std::endl;
    std::cout << "[KoR-VERIFY] Result = " << (result ? "PASSED" : "FAILED") << std::endl;
    
    // Clean up
    element_clear(c_copy);
    element_clear(s1_copy);
    element_clear(s2_copy);
    element_clear(s3_copy);
    element_clear(com);
    element_clear(one_minus_c);
    element_clear(k_prime_prime);
    element_clear(g2_s1);
    element_clear(alpha2_copy);
    element_clear(alpha2_pow);
    element_clear(beta2_copy);
    element_clear(beta2_s2);
    element_clear(k_copy);
    element_clear(com_prime_prime);
    element_clear(g1_s3);
    element_clear(h_s2);
    element_clear(com_c);
    element_clear(c_prime);
    
    return result;
}