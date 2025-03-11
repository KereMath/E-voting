#include "kor.h"
#include <openssl/sha.h>
#include <sstream>
#include <iomanip>
#include <stdexcept>
#include <iostream>
#include <vector>

// External function declarations
extern std::string elementToStringG1(const element_t elem);
extern std::string elementToStringG2(const element_t elem);

KoRProof createKoRProof(
    TIACParams &params,
    const element_t h,
    const element_t k,
    const element_t com,
    const element_t alpha2,
    const element_t beta2,
    const element_t r,
    const element_t did_elem,
    const element_t o_elem
) {
    KoRProof proof;
    
    // Initialize result elements
    element_init_Zr(proof.c, params.pairing);
    element_init_Zr(proof.s1, params.pairing);
    element_init_Zr(proof.s2, params.pairing);
    element_init_Zr(proof.s3, params.pairing);
    
    // Step 1: Choose random r1', r2', r3' in Zp.
    element_t r1p, r2p, r3p;
    element_init_Zr(r1p, params.pairing);
    element_init_Zr(r2p, params.pairing);
    element_init_Zr(r3p, params.pairing);
    element_random(r1p);
    element_random(r2p);
    element_random(r3p);
    
    // Step 2: Compute k' = g2^(r1') * α₂ * (β₂)^(r2')
    element_t k_prime;
    element_init_G2(k_prime, params.pairing);
    element_t g2_r1p, beta2_r2p;
    element_init_G2(g2_r1p, params.pairing);
    element_init_G2(beta2_r2p, params.pairing);

    element_pow_zn(g2_r1p, params.g2, r1p);
    element_pow_zn(beta2_r2p, const_cast<element_t>(beta2), r2p);
    element_mul(k_prime, g2_r1p, const_cast<element_t>(alpha2));
    element_mul(k_prime, k_prime, beta2_r2p);
    
    // Step 3: Compute com' = g1^(r3') * h^(r2')
    element_t com_prime;
    element_init_G1(com_prime, params.pairing);
    element_t g1_r3p, h_r2p;
    element_init_G1(g1_r3p, params.pairing);
    element_init_G1(h_r2p, params.pairing);
    element_pow_zn(g1_r3p, params.g1, r3p);
    element_pow_zn(h_r2p, const_cast<element_t>(h), r2p);
    element_mul(com_prime, g1_r3p, h_r2p);
    
    // Step 4: Compute c = Hash(g1, g2, h, com, com', k, k')
    std::ostringstream hashOSS;
    hashOSS << elementToStringG1(params.g1)
            << elementToStringG2(params.g2)
            << elementToStringG1(h)
            << elementToStringG1(com)
            << elementToStringG1(com_prime)
            << elementToStringG2(k)
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
    
    // Convert hash to element c in Zp.
    mpz_t c_mpz;
    mpz_init(c_mpz);
    if(mpz_set_str(c_mpz, c_str.c_str(), 16) != 0)
        throw std::runtime_error("createKoRProof: Error converting hash to mpz");
    mpz_mod(c_mpz, c_mpz, params.prime_order);
    element_t c_elem;
    element_init_Zr(c_elem, params.pairing);
    element_set_mpz(c_elem, c_mpz);
    mpz_clear(c_mpz);
    
    // Step 5: Compute s1 = r1' − c · r.
    element_t temp;
    element_init_Zr(temp, params.pairing);
    element_mul(temp, c_elem, const_cast<element_t>(r));
    element_sub(proof.s1, r1p, temp);
    element_clear(temp);
    
    // Step 6: Compute s2 = r2' − c · (didInt).
    element_t temp2;
    element_init_Zr(temp2, params.pairing);
    element_mul(temp2, c_elem, const_cast<element_t>(did_elem));
    element_sub(proof.s2, r2p, temp2);
    element_clear(temp2);
    
    // Step 7: Compute s3 = r3' − c · o.
    element_t temp3;
    element_init_Zr(temp3, params.pairing);
    element_mul(temp3, c_elem, const_cast<element_t>(o_elem));
    element_sub(proof.s3, r3p, temp3);
    element_clear(temp3);
    
    // Set c element in result
    element_set(proof.c, c_elem);
    
    // Step 8: Construct the KoR tuple string: π_v = (c, s1, s2, s3)
    std::ostringstream korOSS;
    korOSS << elementToStringG1(c_elem) << " "
           << elementToStringG1(proof.s1) << " "
           << elementToStringG1(proof.s2) << " "
           << elementToStringG1(proof.s3);
    proof.proof_v = korOSS.str();
    
    // Debug output
    std::cout << "[KoR] Creating KoR proof with elements:" << std::endl;
    std::cout << "[KoR] c = " << elementToStringG1(c_elem).substr(0, 20) << "..." << std::endl;
    std::cout << "[KoR] s1 = " << elementToStringG1(proof.s1).substr(0, 20) << "..." << std::endl;
    std::cout << "[KoR] s2 = " << elementToStringG1(proof.s2).substr(0, 20) << "..." << std::endl;
    std::cout << "[KoR] s3 = " << elementToStringG1(proof.s3).substr(0, 20) << "..." << std::endl;
    
    // Cleanup
    element_clear(r1p);
    element_clear(r2p);
    element_clear(r3p);
    element_clear(k_prime);
    element_clear(g2_r1p);
    element_clear(beta2_r2p);
    element_clear(g1_r3p);
    element_clear(h_r2p);
    element_clear(com_prime);
    element_clear(c_elem);
    
    return proof;
}