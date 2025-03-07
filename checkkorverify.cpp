#include "checkkorverify.h"
#include <sstream>
#include <iostream>
#include <vector>
#include <openssl/sha.h>
#include <cstring>
#include <iomanip>

// Use the same elemToStrG1 function as in blindsign.h
std::string elementToStringG1(element_t elem) {
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

// Parse the KoR proof tuple from string
bool parseKoRProof(const std::string &proof_v, element_t c, element_t s1, element_t s2, element_t s3, pairing_t pairing) {
    std::istringstream ss(proof_v);
    std::string c_str, s1_str, s2_str, s3_str;
    
    if (!(ss >> c_str >> s1_str >> s2_str >> s3_str)) {
        std::cerr << "Failed to parse KoR proof elements\n";
        return false;
    }
    
    // Debug output
    std::cout << "[KoR-VERIFY] Parsing proof string: " << proof_v << std::endl;
    std::cout << "[KoR-VERIFY] c_str: " << c_str << std::endl;
    
    if (!elementFromHexString(c_str, c, pairing, true) ||
        !elementFromHexString(s1_str, s1, pairing, true) ||
        !elementFromHexString(s2_str, s2, pairing, true) ||
        !elementFromHexString(s3_str, s3, pairing, true)) {
        std::cerr << "Failed to extract elements from hex strings\n";
        return false;
    }
    
    return true;
}

// Consistent hashToZr function matching the one in blindsign.cpp
void hashToZr(element_t outZr, TIACParams &params, const std::vector<element_t> &elements) {
    std::ostringstream oss;
    for (auto elem : elements) {
        oss << elementToStringG1(elem);
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
    if (!elementFromHexString(comStr, com, params.pairing)) {
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
    
    // Compute the hash using the same method as in blindsign.cpp
    element_t c_prime;
    element_init_Zr(c_prime, params.pairing);
    
    std::vector<element_t> toHash;
    toHash.push_back(params.g1);
    toHash.push_back(params.g2);
    toHash.push_back(params.h1);
    toHash.push_back(com);
    toHash.push_back(com_prime_prime);
    toHash.push_back(k_copy);
    toHash.push_back(k_prime_prime);
    
    hashToZr(c_prime, params, toHash);
    
    // Check if c_prime == c
    bool result = (element_cmp(c_prime, c) == 0);
    
    // Debug output
    std::cout << "[KoR-VERIFY] c      = " << elementToStringG1(c) << std::endl;
    std::cout << "[KoR-VERIFY] c'     = " << elementToStringG1(c_prime) << std::endl;
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
    
    return result;
}