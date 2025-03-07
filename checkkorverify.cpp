#include "checkkorverify.h"
#include <sstream>
#include <iostream>
#include <vector>
#include <openssl/sha.h>
#include <cstring>  // For strlen
#include <iomanip>  // For setw, setfill

// Helper function to handle const element_s* (make a non-const copy)
static inline element_s* toNonConst(const element_s* in) {
    return const_cast<element_s*>(in);
}

// Helper function to extract element from string
bool extractElementFromString(const std::string &input, element_t output, pairing_t pairing, bool isZr = false) {
    try {
        if (isZr) {
            element_init_Zr(output, pairing);
        } else {
            element_init_G1(output, pairing);
        }
        int result = element_set_str(output, input.c_str(), 10);
        return result == 0;
    } catch (...) {
        return false;
    }
}

// Parse the KoR proof tuple from string
bool parseKoRProof(const std::string &proof_v, element_t c, element_t s1, element_t s2, element_t s3, pairing_t pairing) {
    std::istringstream ss(proof_v);
    std::string c_str, s1_str, s2_str, s3_str;
    
    if (!(ss >> c_str >> s1_str >> s2_str >> s3_str)) {
        std::cerr << "Failed to parse KoR proof elements\n";
        return false;
    }
    
    if (!extractElementFromString(c_str, c, pairing, true) ||
        !extractElementFromString(s1_str, s1, pairing, true) ||
        !extractElementFromString(s2_str, s2, pairing, true) ||
        !extractElementFromString(s3_str, s3, pairing, true)) {
        std::cerr << "Failed to extract elements from strings\n";
        return false;
    }
    
    return true;
}

// Compute hash of multiple elements
std::string computeHash(
    element_t g1, element_t g2, element_t h,
    element_t com, element_t com_prime_prime,
    element_t k, element_t k_prime_prime,
    pairing_t pairing
) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    
    char buffer[1024];
    
    // Add g1 to hash
    element_snprintf(buffer, sizeof(buffer), "%B", g1);
    SHA256_Update(&sha256, buffer, strlen(buffer));
    
    // Add g2 to hash
    element_snprintf(buffer, sizeof(buffer), "%B", g2);
    SHA256_Update(&sha256, buffer, strlen(buffer));
    
    // Add h to hash
    element_snprintf(buffer, sizeof(buffer), "%B", h);
    SHA256_Update(&sha256, buffer, strlen(buffer));
    
    // Add com to hash
    element_snprintf(buffer, sizeof(buffer), "%B", com);
    SHA256_Update(&sha256, buffer, strlen(buffer));
    
    // Add com_prime_prime to hash
    element_snprintf(buffer, sizeof(buffer), "%B", com_prime_prime);
    SHA256_Update(&sha256, buffer, strlen(buffer));
    
    // Add k to hash
    element_snprintf(buffer, sizeof(buffer), "%B", k);
    SHA256_Update(&sha256, buffer, strlen(buffer));
    
    // Add k_prime_prime to hash
    element_snprintf(buffer, sizeof(buffer), "%B", k_prime_prime);
    SHA256_Update(&sha256, buffer, strlen(buffer));
    
    SHA256_Final(hash, &sha256);
    
    // Convert hash to hex string
    std::stringstream ss;
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(hash[i]);
    }
    
    return ss.str();
}

bool checkKoRVerify(
    TIACParams &params,
    const ProveCredentialOutput &proveOutput,
    const MasterVerKey &mvk,
    const std::string &comStr
) {
    std::cout << "[KoR-VERIFY] Starting Knowledge of Representation verification..." << std::endl;
    
    // Parse the proof elements
    element_t c, s1, s2, s3;
    if (!parseKoRProof(proveOutput.proof_v, c, s1, s2, s3, params.pairing)) {
        std::cerr << "[KoR-VERIFY] Failed to parse proof elements!" << std::endl;
        return false;
    }
    
    // Parse the commitment
    element_t com;
    element_init_G1(com, params.pairing);
    if (element_set_str(com, comStr.c_str(), 10) != 0) {
        std::cerr << "[KoR-VERIFY] Failed to parse commitment!" << std::endl;
        element_clear(com);
        return false;
    }
    
    // Calculate 1-c
    element_t one_minus_c;
    element_init_Zr(one_minus_c, params.pairing);
    element_set1(one_minus_c);
    element_sub(one_minus_c, one_minus_c, c);
    
    // Calculate k_prime_prime = g2^(s1) * alpha2^(1-c) * k * beta2^s2
    element_t k_prime_prime;
    element_init_G2(k_prime_prime, params.pairing);
    
    // g2^(s1)
    element_t g2_s1;
    element_init_G2(g2_s1, params.pairing);
    element_pow_zn(g2_s1, params.g2, s1);
    
    // alpha2^(1-c)
    element_t alpha2_pow, alpha2_copy;
    element_init_G2(alpha2_pow, params.pairing);
    element_init_G2(alpha2_copy, params.pairing);
    element_set(alpha2_copy, toNonConst(&mvk.alpha2[0]));
    element_pow_zn(alpha2_pow, alpha2_copy, one_minus_c);
    
    // beta2^s2
    element_t beta2_s2, beta2_copy;
    element_init_G2(beta2_s2, params.pairing);
    element_init_G2(beta2_copy, params.pairing);
    element_set(beta2_copy, toNonConst(&mvk.beta2[0]));
    element_pow_zn(beta2_s2, beta2_copy, s2);
    
    // Create a copy of k for non-const use
    element_t k_copy;
    element_init_G2(k_copy, params.pairing);
    element_set(k_copy, toNonConst(&proveOutput.k[0]));
    
    // Multiply all components
    element_mul(k_prime_prime, g2_s1, alpha2_pow);
    element_mul(k_prime_prime, k_prime_prime, k_copy);
    element_mul(k_prime_prime, k_prime_prime, beta2_s2);
    
    // Calculate com_prime_prime = g1^s3 * h^s2 * com^c
    element_t com_prime_prime;
    element_init_G1(com_prime_prime, params.pairing);
    
    // g1^s3
    element_t g1_s3;
    element_init_G1(g1_s3, params.pairing);
    element_pow_zn(g1_s3, params.g1, s3);
    
    // h^s2
    element_t h_s2;
    element_init_G1(h_s2, params.pairing);
    element_pow_zn(h_s2, params.h1, s2);
    
    // com^c
    element_t com_c;
    element_init_G1(com_c, params.pairing);
    element_pow_zn(com_c, com, c);
    
    // Multiply all components
    element_mul(com_prime_prime, g1_s3, h_s2);
    element_mul(com_prime_prime, com_prime_prime, com_c);
    
    // Compute c_prime = hash(g1, g2, h, com, com_prime_prime, k, k_prime_prime)
    std::string hash_result = computeHash(
        params.g1, params.g2, params.h1,
        com, com_prime_prime,
        k_copy, k_prime_prime,
        params.pairing
    );
    
    // Convert hash to element for comparison
    element_t c_prime;
    element_init_Zr(c_prime, params.pairing);
    mpz_t hash_mpz;
    mpz_init(hash_mpz);
    mpz_set_str(hash_mpz, hash_result.c_str(), 16);
    mpz_mod(hash_mpz, hash_mpz, params.prime_order);
    element_set_mpz(c_prime, hash_mpz);
    
    // Check if c_prime == c
    bool result = (element_cmp(c_prime, c) == 0);
    
    // Debug output
    char c_buf[1024], c_prime_buf[1024];
    element_snprintf(c_buf, sizeof(c_buf), "%B", c);
    element_snprintf(c_prime_buf, sizeof(c_prime_buf), "%B", c_prime);
    std::cout << "[KoR-VERIFY] c      = " << c_buf << std::endl;
    std::cout << "[KoR-VERIFY] c'     = " << c_prime_buf << std::endl;
    std::cout << "[KoR-VERIFY] Result = " << (result ? "PASSED" : "FAILED") << std::endl;
    
    // Clean up
    element_clear(c);
    element_clear(s1);
    element_clear(s2);
    element_clear(s3);
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
    mpz_clear(hash_mpz);
    
    return result;
}