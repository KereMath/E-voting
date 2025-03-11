#include "provecredential.h"
#include <openssl/sha.h>
#include <sstream>
#include <iomanip>
#include <stdexcept>
#include <iostream>

// Dışarıdan tanımlı: elementToStringG1 (const parametre alır)
extern std::string elementToStringG1(const element_t elem);

// New function for G2 elements
static std::string elementToStringG2(const element_t elem) {
    // Use toNonConst to handle the const parameter
    element_t elem_nonconst;
    elem_nonconst[0] = *((element_s*)(&elem[0]));
    
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

// Helper: Convert an mpz_t value to std::string.
static std::string mpzToString(const mpz_t value) {
    char* c_str = mpz_get_str(nullptr, 10, value);
    std::string str(c_str);
    free(c_str);
    return str;
}

ProveCredentialOutput proveCredential(
    TIACParams &params,
    AggregateSignature &aggSig,
    MasterVerKey &mvk,
    const std::string &didStr,
    const mpz_t o   // "o" value from prepare phase
) {
    ProveCredentialOutput output;
    
    // --- Step 1: Choose random r and r' in Zp ---
    element_t r, r_prime;
    element_init_Zr(r, params.pairing);
    element_init_Zr(r_prime, params.pairing);
    element_random(r);
    element_random(r_prime);
    
    // --- Step 2: Compute h'' = h^(r') ---
    element_t h_dbl;
    element_init_G1(h_dbl, params.pairing);
    element_pow_zn(h_dbl, aggSig.h, r_prime);
    
    // --- Step 3: Compute s'' = s^(r') * (h'')^(r) ---
    element_t s_rprime, h_pp_r, s_dbl;
    element_init_G1(s_rprime, params.pairing);
    element_init_G1(h_pp_r, params.pairing);
    element_init_G1(s_dbl, params.pairing);
    element_pow_zn(s_rprime, aggSig.s, r_prime);
    element_pow_zn(h_pp_r, h_dbl, r);
    element_mul(s_dbl, s_rprime, h_pp_r);
    
    // --- Step 4: Set σ″ = (h'', s'') ---
    element_init_G1(output.sigmaRnd.h, params.pairing);
    element_set(output.sigmaRnd.h, h_dbl);
    element_init_G1(output.sigmaRnd.s, params.pairing);
    element_set(output.sigmaRnd.s, s_dbl);
    
    // --- Step 5: Process DID ---
    mpz_t didInt;
    mpz_init(didInt);
    if (mpz_set_str(didInt, didStr.c_str(), 16) != 0)
        throw std::runtime_error("proveCredential: Invalid DID hex string");
    mpz_mod(didInt, didInt, params.prime_order);
    
    // --- Step 6: Compute k = α₂ * (β₂)^(didInt) * g₂^(r) ---
    element_t beta_exp, g2_r;
    element_init_G2(beta_exp, params.pairing);  // Changed to G2
    element_t expElem;
    element_init_Zr(expElem, params.pairing);
    element_set_mpz(expElem, didInt);
    element_pow_zn(beta_exp, mvk.beta2, expElem);
    element_clear(expElem);
    element_init_G2(g2_r, params.pairing);  // Changed to G2
    element_pow_zn(g2_r, params.g2, r);
    element_init_G2(output.k, params.pairing);  // Changed to G2
    element_mul(output.k, mvk.alpha2, beta_exp);
    element_mul(output.k, output.k, g2_r);
    
    // --- Step 7: Compute KoR tuple (Algorithm 16) ---
    // 7.1: Choose random r1', r2', r3' in Zp.
    element_t r1p, r2p, r3p;
    element_init_Zr(r1p, params.pairing);
    element_init_Zr(r2p, params.pairing);
    element_init_Zr(r3p, params.pairing);
    element_random(r1p);
    element_random(r2p);
    element_random(r3p);
    
    // 7.2: Compute k' = g2^(r1') * α₂ * (β₂)^(r2')
    element_t k_prime;
    element_init_G2(k_prime, params.pairing);
    element_t g2_r1p, beta2_r2p;
    element_init_G2(g2_r1p, params.pairing);
    element_init_G2(beta2_r2p, params.pairing);

    element_pow_zn(g2_r1p, params.g2, r1p);
    element_pow_zn(beta2_r2p, mvk.beta2, r2p);
    element_mul(k_prime, g2_r1p, mvk.alpha2);
    element_mul(k_prime, k_prime, beta2_r2p);
    
    // 7.3: Compute com' = g1^(r3') * h^(r2') - FIXED: now using aggSig.h instead of params.h1
    element_t com_prime;
    element_init_G1(com_prime, params.pairing);
    element_t g1_r3p, h_r2p;
    element_init_G1(g1_r3p, params.pairing);
    element_init_G1(h_r2p, params.pairing);
    element_pow_zn(g1_r3p, params.g1, r3p);
    element_pow_zn(h_r2p, aggSig.h, r2p);  // Using aggSig.h instead of params.h1
    element_mul(com_prime, g1_r3p, h_r2p);
    
    // Create a com element for the hash calculation - this is g1^o * h^DIDi
    element_t com;
    element_init_G1(com, params.pairing);
    element_t g1_o, h_did;
    element_init_G1(g1_o, params.pairing);
    element_init_G1(h_did, params.pairing);
    
    // g1^o
    element_t o_elem;
    element_init_Zr(o_elem, params.pairing);
    mpz_t temp;
    mpz_init(temp);
    mpz_set(temp, o);
    element_set_mpz(o_elem, temp);
    mpz_clear(temp);
    element_pow_zn(g1_o, params.g1, o_elem);
    
    // h^DIDi - Using aggSig.h here too
    element_t did_elem;
    element_init_Zr(did_elem, params.pairing);
    element_set_mpz(did_elem, didInt);
    element_pow_zn(h_did, aggSig.h, did_elem);  // Changed to aggSig.h
    
    // com = g1^o * h^DIDi
    element_mul(com, g1_o, h_did);
    
    // 7.4: Compute c = Hash(g1, g2, h, com, com', k, k') - Using aggSig.h and proper serialization
    std::ostringstream hashOSS;
    hashOSS << elementToStringG1(params.g1)
            << elementToStringG2(params.g2)  // Use G2 serialization
            << elementToStringG1(aggSig.h)   // Use aggSig.h instead of params.h1
            << elementToStringG1(com)
            << elementToStringG1(com_prime)
            << elementToStringG2(output.k)   // Use G2 serialization
            << elementToStringG2(k_prime);   // Use G2 serialization
    std::string hashInput = hashOSS.str();
    
    unsigned char hashDigest[SHA512_DIGEST_LENGTH];
    SHA512(reinterpret_cast<const unsigned char*>(hashInput.data()), hashInput.size(), hashDigest);
    std::ostringstream hashFinalOSS;
    hashFinalOSS << std::hex << std::setfill('0');
    for (int i = 0; i < SHA512_DIGEST_LENGTH; i++) {
        hashFinalOSS << std::setw(2) << (int)hashDigest[i];
    }
    std::string c_str = hashFinalOSS.str();
    
    // 7.5: Convert hash to element c in Zp.
    mpz_t c_mpz;
    mpz_init(c_mpz);
    if(mpz_set_str(c_mpz, c_str.c_str(), 16) != 0)
        throw std::runtime_error("proveCredential: Error converting hash to mpz");
    mpz_mod(c_mpz, c_mpz, params.prime_order);
    element_t c_elem;
    element_init_Zr(c_elem, params.pairing);
    element_set_mpz(c_elem, c_mpz);
    mpz_clear(c_mpz);
    
    // 7.6: Compute s1 = r1' − c · r.
    element_t s1, s2, s3;
    element_init_Zr(s1, params.pairing);
    element_init_Zr(s2, params.pairing);
    element_init_Zr(s3, params.pairing);
    {
        element_t temp;
        element_init_Zr(temp, params.pairing);
        element_mul(temp, c_elem, r);
        element_sub(s1, r1p, temp);
        element_clear(temp);
    }
    
    // 7.7: Compute s2 = r2' − c · (didInt).
    element_t temp2;
    element_init_Zr(temp2, params.pairing);
    element_mul(temp2, c_elem, did_elem);  // Using did_elem which we already set up
    element_sub(s2, r2p, temp2);
    element_clear(temp2);
    
    // 7.8: Compute s3 = r3' − c · o.
    element_t temp3;
    element_init_Zr(temp3, params.pairing);
    element_mul(temp3, c_elem, o_elem);  // Using o_elem which we already set up
    element_sub(s3, r3p, temp3);
    element_clear(temp3);
    
    // Store the proof elements directly in the output struct
    element_init_Zr(output.c, params.pairing);
    element_init_Zr(output.s1, params.pairing);
    element_init_Zr(output.s2, params.pairing);
    element_init_Zr(output.s3, params.pairing);
    
    element_set(output.c, c_elem);
    element_set(output.s1, s1);
    element_set(output.s2, s2);
    element_set(output.s3, s3);
    
    // 7.9: Also construct the KoR tuple string for backwards compatibility: π_v = (c, s1, s2, s3)
    std::ostringstream korOSS;
    korOSS << elementToStringG1(c_elem) << " "
           << elementToStringG1(s1) << " "
           << elementToStringG1(s2) << " "
           << elementToStringG1(s3);
    std::string kor_tuple = korOSS.str();
    
    output.proof_v = kor_tuple;
    
    // --- Debug information ---
    std::ostringstream dbg;
    dbg << "h'' = " << elementToStringG1(output.sigmaRnd.h) << "\n";
    dbg << "s'' = " << elementToStringG1(output.sigmaRnd.s) << "\n";
    dbg << "k   = " << elementToStringG2(output.k) << "\n";  // Updated to G2 serialization
    dbg << "KoR tuple = " << output.proof_v << "\n";
    output.sigmaRnd.debug_info = dbg.str();
    
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
    element_clear(s1);
    element_clear(s2);
    element_clear(s3);
    element_clear(o_elem);
    element_clear(did_elem);
    element_clear(com);
    element_clear(g1_o);
    element_clear(h_did);
    element_clear(r);
    element_clear(r_prime);
    element_clear(h_dbl);
    element_clear(s_rprime);
    element_clear(h_pp_r);
    element_clear(s_dbl);
    element_clear(beta_exp);
    element_clear(g2_r);
    mpz_clear(didInt);
    
    return output;
}