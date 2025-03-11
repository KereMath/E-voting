#include "kor.h"
#include <openssl/sha.h>
#include <sstream>
#include <iomanip>
#include <stdexcept>
#include <iostream>
#include <vector>

// Element serialization functions
std::string elementToStringG1(const element_t elem) {
    // Create a non-const copy to work with
    element_t elem_copy;
    elem_copy[0] = *((element_s*)(&elem[0]));
    
    int len = element_length_in_bytes(elem_copy);
    std::vector<unsigned char> buf(len);
    element_to_bytes(buf.data(), elem_copy);

    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (unsigned char c : buf) {
        oss << std::setw(2) << (int)c;
    }
    return oss.str();
}

std::string elementToStringG2(const element_t elem) {
    // Create a non-const copy to work with
    element_t elem_copy;
    elem_copy[0] = *((element_s*)(&elem[0]));
    
    int len = element_length_in_bytes(elem_copy);
    std::vector<unsigned char> buf(len);
    element_to_bytes(buf.data(), elem_copy);

    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (unsigned char c : buf) {
        oss << std::setw(2) << (int)c;
    }
    return oss.str();
}
// Helper function to convert hex string to bytes
static std::vector<unsigned char> hexToBytes(const std::string& hex) {
    std::vector<unsigned char> bytes;
    bytes.reserve(hex.length() / 2);
    
    for (size_t i = 0; i + 1 < hex.length(); i += 2) {
        std::string byteStr = hex.substr(i, 2);
        unsigned char byte = (unsigned char)strtol(byteStr.c_str(), NULL, 16);
        bytes.push_back(byte);
    }
    
    return bytes;
}

// Helper function to convert string to element_t
void stringToElement(element_t result, const std::string &str, pairing_t pairing, int element_type) {
    // Initialize the result element
    switch (element_type) {
        case 1: // G1
            element_init_G1(result, pairing);
            break;
        case 2: // G2
            element_init_G2(result, pairing);
            break;
        default: // Zr or other
            element_init_Zr(result, pairing);
            break;
    }
    
    // Convert the string to bytes
    std::vector<unsigned char> bytes = hexToBytes(str);
    if (bytes.empty()) {
        throw std::runtime_error("Failed to convert hex string to bytes");
    }
    
    // Convert bytes to element
    if (element_from_bytes(result, bytes.data()) == 0) {
        throw std::runtime_error("Failed to create element from bytes");
    }
}

// Helper function to create a non-const copy of an element
static void copy_const_element(element_t dest, const element_t src, pairing_t pairing, int element_type) {
    // Initialize dest with the appropriate type
    switch (element_type) {
        case 1: // G1
            element_init_G1(dest, pairing);
            break;
        case 2: // G2
            element_init_G2(dest, pairing);
            break;
        default: // Zr or other
            element_init_Zr(dest, pairing);
            break;
    }
    
    // Create a temporary non-const element that's a copy of the source
    element_t temp;
    // Copy the source element structure
    temp[0] = *((element_s*)(&src[0]));
    
    // Now we can use temp with PBC functions that don't accept const
    element_set(dest, temp);
}

// Helper function to create a non-const copy of mpz_t
static void copy_const_mpz(mpz_t dest, const mpz_t src) {
    mpz_init(dest);
    mpz_set(dest, src);
}

KnowledgeOfRepProof generateKoRProof(
    TIACParams &params,
    const element_t h,
    const element_t k,
    const element_t com,
    const element_t alpha2,
    const element_t beta2,
    const element_t r,
    const mpz_t did_int,
    const mpz_t o
) {
    std::cout << "Starting Knowledge of Representation (KoR) algorithm..." << std::endl;
    
    KnowledgeOfRepProof proof;
    
    // Initialize result elements
    element_init_Zr(proof.c, params.pairing);
    element_init_Zr(proof.s1, params.pairing);
    element_init_Zr(proof.s2, params.pairing);
    element_init_Zr(proof.s3, params.pairing);
    
    // Create non-const copies of all const inputs
    element_t h_copy, k_copy, com_copy, alpha2_copy, beta2_copy, r_copy;
    
    copy_const_element(h_copy, h, params.pairing, 1);        // G1
    copy_const_element(k_copy, k, params.pairing, 2);        // G2
    copy_const_element(com_copy, com, params.pairing, 1);    // G1
    copy_const_element(alpha2_copy, alpha2, params.pairing, 2); // G2
    copy_const_element(beta2_copy, beta2, params.pairing, 2);  // G2
    copy_const_element(r_copy, r, params.pairing, 0);        // Zr
    
    // Create non-const copies of mpz_t values
    mpz_t did_int_copy, o_copy;
    copy_const_mpz(did_int_copy, did_int);
    copy_const_mpz(o_copy, o);
    
    // Convert mpz_t values to Zr elements
    element_t did_elem, o_elem;
    element_init_Zr(did_elem, params.pairing);
    element_init_Zr(o_elem, params.pairing);
    element_set_mpz(did_elem, did_int_copy);
    element_set_mpz(o_elem, o_copy);
    
    // Step 1: Choose random r1, r2, r3 in Zp
    element_t r1, r2, r3;
    element_init_Zr(r1, params.pairing);
    element_init_Zr(r2, params.pairing);
    element_init_Zr(r3, params.pairing);
    element_random(r1);
    element_random(r2);
    element_random(r3);
    
    std::cout << "KoR Step 1: Generated random exponents r1, r2, r3" << std::endl;
    
    // Step 2: Compute k' = g2^(r1) * α₂ * (β₂)^(r2)
    element_t k_prime;
    element_init_G2(k_prime, params.pairing);
    element_t g2_r1, beta2_r2;
    element_init_G2(g2_r1, params.pairing);
    element_init_G2(beta2_r2, params.pairing);

    element_pow_zn(g2_r1, params.g2, r1);
    element_pow_zn(beta2_r2, beta2_copy, r2);
    element_mul(k_prime, g2_r1, alpha2_copy);
    element_mul(k_prime, k_prime, beta2_r2);
    
    std::cout << "KoR Step 2: Computed k'" << std::endl;
    
    // Step 3: Compute com' = g1^(r3) * h^(r2)
    element_t com_prime;
    element_init_G1(com_prime, params.pairing);
    element_t g1_r3, h_r2;
    element_init_G1(g1_r3, params.pairing);
    element_init_G1(h_r2, params.pairing);
    element_pow_zn(g1_r3, params.g1, r3);
    element_pow_zn(h_r2, h_copy, r2);
    element_mul(com_prime, g1_r3, h_r2);
    
    std::cout << "KoR Step 3: Computed com'" << std::endl;
    
    // Step 4: Compute c = Hash(g1, g2, h, com, com', k, k')
    std::ostringstream hashOSS;
    hashOSS << elementToStringG1(params.g1)
            << elementToStringG2(params.g2)
            << elementToStringG1(h_copy)
            << elementToStringG1(com_copy)
            << elementToStringG1(com_prime)
            << elementToStringG2(k_copy)
            << elementToStringG2(k_prime);
    std::string hashInput = hashOSS.str();
    
    // Calculate SHA-512 hash
    unsigned char hashDigest[SHA512_DIGEST_LENGTH];
    SHA512(reinterpret_cast<const unsigned char*>(hashInput.data()), hashInput.size(), hashDigest);
    std::ostringstream hashFinalOSS;
    hashFinalOSS << std::hex << std::setfill('0');
    for (int i = 0; i < SHA512_DIGEST_LENGTH; i++) {
        hashFinalOSS << std::setw(2) << (int)hashDigest[i];
    }
    std::string c_str = hashFinalOSS.str();
    
    // Convert hash to element c in Zp
    mpz_t c_mpz;
    mpz_init(c_mpz);
    if(mpz_set_str(c_mpz, c_str.c_str(), 16) != 0)
        throw std::runtime_error("generateKoRProof: Error converting hash to mpz");
    mpz_mod(c_mpz, c_mpz, params.prime_order);
    element_t c_elem;
    element_init_Zr(c_elem, params.pairing);
    element_set_mpz(c_elem, c_mpz);
    mpz_clear(c_mpz);
    
    std::cout << "KoR Step 4: Computed challenge c" << std::endl;
    
    // Step 5: Compute s1 = r1 - c·r
    element_t temp;
    element_init_Zr(temp, params.pairing);
    element_mul(temp, c_elem, r_copy);
    element_sub(proof.s1, r1, temp);
    element_clear(temp);
    
    std::cout << "KoR Step 5: Computed s1" << std::endl;
    
    // Step 6: Compute s2 = r2 - c·DIDi
    element_t temp2;
    element_init_Zr(temp2, params.pairing);
    element_mul(temp2, c_elem, did_elem);
    element_sub(proof.s2, r2, temp2);
    element_clear(temp2);
    
    std::cout << "KoR Step 6: Computed s2" << std::endl;
    
    // Step 7: Compute s3 = r3 - c·o
    element_t temp3;
    element_init_Zr(temp3, params.pairing);
    element_mul(temp3, c_elem, o_elem);
    element_sub(proof.s3, r3, temp3);
    element_clear(temp3);
    
    std::cout << "KoR Step 7: Computed s3" << std::endl;
    
    // Set c element in result
    element_set(proof.c, c_elem);
    
    // Step 8: Construct the KoR tuple string: πv = (c, s1, s2, s3)
    std::ostringstream korOSS;
    korOSS << elementToStringG1(c_elem) << " "
           << elementToStringG1(proof.s1) << " "
           << elementToStringG1(proof.s2) << " "
           << elementToStringG1(proof.s3);
    
    // Set the proof string
    proof.proof_string = korOSS.str();
    
    std::cout << "KoR Step 8: Constructed tuple (c, s1, s2, s3)" << std::endl;
    
    // Debug output
    std::cout << "KoR algorithm completed successfully." << std::endl;
    
    // Clean up temporary elements
    element_clear(h_copy);
    element_clear(k_copy);
    element_clear(com_copy);
    element_clear(alpha2_copy);
    element_clear(beta2_copy);
    element_clear(r_copy);
    element_clear(did_elem);
    element_clear(o_elem);
    element_clear(r1);
    element_clear(r2);
    element_clear(r3);
    element_clear(k_prime);
    element_clear(g2_r1);
    element_clear(beta2_r2);
    element_clear(com_prime);
    element_clear(g1_r3);
    element_clear(h_r2);
    element_clear(c_elem);
    mpz_clear(did_int_copy);
    mpz_clear(o_copy);
    
    return proof;
}