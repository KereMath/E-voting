#include "provecredential.h"
#include "kor.h"  // Include our new KoR header
#include <openssl/sha.h>
#include <sstream>
#include <iomanip>
#include <stdexcept>
#include <iostream>
#include <vector>

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
    
    // Create element representations for o and didInt
    element_t o_elem, did_elem;
    element_init_Zr(o_elem, params.pairing);
    element_init_Zr(did_elem, params.pairing);
    mpz_t temp;
    mpz_init(temp);
    mpz_set(temp, o);
    element_set_mpz(o_elem, temp);
    mpz_clear(temp);
    element_set_mpz(did_elem, didInt);
    
    // Create a com element for the hash calculation - this is g1^o * h^DIDi
    element_t com;
    element_init_G1(com, params.pairing);
    element_t g1_o, h_did;
    element_init_G1(g1_o, params.pairing);
    element_init_G1(h_did, params.pairing);
    
    // g1^o
    element_pow_zn(g1_o, params.g1, o_elem);
    
    // h^DIDi - Using aggSig.h
    element_pow_zn(h_did, aggSig.h, did_elem);
    
    // com = g1^o * h^DIDi
    element_mul(com, g1_o, h_did);
    
    // --- Step 7: Call the Knowledge of Representation (KoR) algorithm ---
    std::cout << "[ProveCredential] Calling KoR algorithm..." << std::endl;
    KoRProof korProof = createKoRProof(
        params,
        aggSig.h,
        output.k,
        com,
        mvk.alpha2,
        mvk.beta2,
        r,
        did_elem,
        o_elem
    );
    
    // Copy the KoR proof to output
    element_init_Zr(output.c, params.pairing);
    element_init_Zr(output.s1, params.pairing);
    element_init_Zr(output.s2, params.pairing);
    element_init_Zr(output.s3, params.pairing);
    
    element_set(output.c, korProof.c);
    element_set(output.s1, korProof.s1);
    element_set(output.s2, korProof.s2);
    element_set(output.s3, korProof.s3);
    output.proof_v = korProof.proof_v;  // Changed from proof_string to proof_v
    
    // --- Debug information ---
    std::ostringstream dbg;
    dbg << "h'' = " << elementToStringG1(output.sigmaRnd.h) << "\n";
    dbg << "s'' = " << elementToStringG1(output.sigmaRnd.s) << "\n";
    dbg << "k   = " << elementToStringG2(output.k) << "\n";  // Updated to G2 serialization
    dbg << "KoR tuple = " << output.proof_v << "\n";
    output.sigmaRnd.debug_info = dbg.str();
    
    // Cleanup
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