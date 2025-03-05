#include "verifycredential.h"
#include <iostream>
#include <sstream>
#include <vector>
#include <iomanip>
#include <openssl/sha.h>

// Dışarıdan tanımlı: elementToStringG1 artık const parametre alır.
extern std::string elementToStringG1(const element_t elem);

// Helper: Convert an mpz_t value to std::string (hex representation)
static std::string mpzToString(const mpz_t value) {
    char* c_str = mpz_get_str(nullptr, 16, value);
    std::string str(c_str);
    free(c_str);
    return str;
}

// Helper: Parse a hex string into a Zr element.
static void parseElement(const std::string &hexStr, element_t &elem, TIACParams &params) {
    mpz_t tmp;
    mpz_init(tmp);
    if (mpz_set_str(tmp, hexStr.c_str(), 16) != 0) {
        throw std::runtime_error("verifyCredential: Error parsing hex string to mpz_t");
    }
    mpz_mod(tmp, tmp, params.prime_order);
    element_set_mpz(elem, tmp);
    mpz_clear(tmp);
}

bool verifyCredential(TIACParams &params,
                      ProveCredentialOutput &pOut,
                      MasterVerKey &mvk,
                      AggregateSignature &aggSig) {
    std::cout << "[VERIFY] Starting credential verification.\n";

    // --- Step 1: Parse the KoR tuple (π_v) from pOut.proof_v ---
    std::istringstream tupleStream(pOut.proof_v);
    std::string c_str, s1_str, s2_str, s3_str;
    if (!(tupleStream >> c_str >> s1_str >> s2_str >> s3_str)) {
        std::cerr << "[VERIFY] Error: Failed to parse KoR tuple from proof_v.\n";
        return false;
    }
    std::cout << "[VERIFY] Parsed KoR tuple:\n"
              << "        c = " << c_str << "\n"
              << "       s1 = " << s1_str << "\n"
              << "       s2 = " << s2_str << "\n"
              << "       s3 = " << s3_str << "\n";

    // --- Step 2: Convert parsed strings to Zr elements ---
    element_t c_elem, s1_elem, s2_elem, s3_elem;
    element_init_Zr(c_elem, params.pairing);
    element_init_Zr(s1_elem, params.pairing);
    element_init_Zr(s2_elem, params.pairing);
    element_init_Zr(s3_elem, params.pairing);
    parseElement(c_str, c_elem, params);
    parseElement(s1_str, s1_elem, params);
    parseElement(s2_str, s2_elem, params);
    parseElement(s3_str, s3_elem, params);

    // --- Step 3: Compute k'' = g1^(s1) · (α₂)^(1-c) · k · (β₂)^(s2) ---
    element_t k_double;
    element_init_G1(k_double, params.pairing);

    element_t part1, part2, part3, part4;
    element_init_G1(part1, params.pairing);
    element_init_G1(part2, params.pairing);
    element_init_G1(part3, params.pairing);
    element_init_G1(part4, params.pairing);
    
    // part1 = g1^(s1)
    element_pow_zn(part1, params.g1, s1_elem);
    std::cout << "[VERIFY] part1 (g1^(s1)): " << elementToStringG1(part1) << "\n";
    
    // Compute (1 - c) in Zr
    element_t one, one_minus_c;
    element_init_Zr(one, params.pairing);
    element_init_Zr(one_minus_c, params.pairing);
    element_set1(one);
    element_sub(one_minus_c, one, c_elem);
    
    // part2 = (α₂)^(1-c)
    element_pow_zn(part2, mvk.alpha2, one_minus_c);
    std::cout << "[VERIFY] part2 (α₂^(1-c)): " << elementToStringG1(part2) << "\n";
    
    // part3 = k (from pOut)
    element_set(part3, pOut.k);
    std::cout << "[VERIFY] part3 (k): " << elementToStringG1(part3) << "\n";
    
    // part4 = (β₂)^(s2)
    element_pow_zn(part4, mvk.beta2, s2_elem);
    std::cout << "[VERIFY] part4 ((β₂)^(s2)): " << elementToStringG1(part4) << "\n";
    
    // Multiply parts to get k_double
    element_mul(k_double, part1, part2);
    element_mul(k_double, k_double, part3);
    element_mul(k_double, k_double, part4);
    std::cout << "[VERIFY] k_double computed: " << elementToStringG1(k_double) << "\n";
    
    // --- Step 4: Compute com'' = g1^(s3) · h^(s2) · (com)^(c) ---
    // Here, we use aggSig.s as "com".
    element_t com_double;
    element_init_G1(com_double, params.pairing);
    
    element_t part5, part6, part7;
    element_init_G1(part5, params.pairing);
    element_init_G1(part6, params.pairing);
    element_init_G1(part7, params.pairing);
    
    // part5 = g1^(s3)
    element_pow_zn(part5, params.g1, s3_elem);
    std::cout << "[VERIFY] part5 (g1^(s3)): " << elementToStringG1(part5) << "\n";
    
    // part6 = h^(s2); here h is pOut.sigmaRnd.h
    element_pow_zn(part6, pOut.sigmaRnd.h, s2_elem);
    std::cout << "[VERIFY] part6 (h^(s2)): " << elementToStringG1(part6) << "\n";
    
    // part7 = (com)^(c); com is taken as aggSig.s
    element_pow_zn(part7, aggSig.s, c_elem);
    std::cout << "[VERIFY] part7 (com^(c)): " << elementToStringG1(part7) << "\n";
    
    element_mul(com_double, part5, part6);
    element_mul(com_double, com_double, part7);
    std::cout << "[VERIFY] com_double computed: " << elementToStringG1(com_double) << "\n";
    
    // --- Step 5: Compute c' = Hash(g1, g2, h, com, com'', k, k'') ---
    std::ostringstream hashOSS;
    hashOSS << elementToStringG1(params.g1)
            << elementToStringG1(params.g2)
            << elementToStringG1(pOut.sigmaRnd.h)
            << elementToStringG1(aggSig.s)   // using aggSig.s as "com"
            << elementToStringG1(com_double)
            << elementToStringG1(pOut.k)
            << elementToStringG1(k_double);
    std::string hashInput = hashOSS.str();
    std::cout << "[VERIFY] Hash input for c': " << hashInput << "\n";
    
    unsigned char hashDigest[SHA512_DIGEST_LENGTH];
    SHA512(reinterpret_cast<const unsigned char*>(hashInput.data()), hashInput.size(), hashDigest);
    std::ostringstream hashFinalOSS;
    hashFinalOSS << std::hex << std::setfill('0');
    for (int i = 0; i < SHA512_DIGEST_LENGTH; i++) {
        hashFinalOSS << std::setw(2) << (int)hashDigest[i];
    }
    std::string c_prime_str = hashFinalOSS.str();
    std::cout << "[VERIFY] Hash output (c'): " << c_prime_str << "\n";
    
    // Convert c_prime_str to an element in Zr.
    element_t c_prime;
    element_init_Zr(c_prime, params.pairing);
    {
        mpz_t tmp;
        mpz_init(tmp);
        if (mpz_set_str(tmp, c_prime_str.c_str(), 16) != 0)
            throw std::runtime_error("verifyCredential: Error converting c_prime string to mpz_t");
        mpz_mod(tmp, tmp, params.prime_order);
        element_set_mpz(c_prime, tmp);
        mpz_clear(tmp);
    }
    std::cout << "[VERIFY] c_prime (as element): " << elementToStringG1(c_prime) << "\n";
    
    // --- Step 6: KoR Check: Verify that c_prime equals c ---
    bool kor_ok = (element_cmp(c_prime, c_elem) == 0);
    std::cout << "[VERIFY] KoR check: " << (kor_ok ? "PASSED" : "FAILED") << "\n";
    
    // --- Step 7: Pairing Check (Algorithm 18) ---
    element_t pairing_lhs, pairing_rhs;
    element_init_GT(pairing_lhs, params.pairing);
    element_init_GT(pairing_rhs, params.pairing);
    pairing_apply(pairing_lhs, pOut.sigmaRnd.h, pOut.k, params.pairing);
    pairing_apply(pairing_rhs, pOut.sigmaRnd.s, params.g2, params.pairing);
    std::string lhsStr = elementToStringG1(pairing_lhs);
    std::string rhsStr = elementToStringG1(pairing_rhs);
    std::cout << "[VERIFY] Pairing LHS = " << lhsStr << "\n";
    std::cout << "[VERIFY] Pairing RHS = " << rhsStr << "\n";
    bool pairing_ok = (element_cmp(pairing_lhs, pairing_rhs) == 0);
    std::cout << "[VERIFY] Pairing check: " << (pairing_ok ? "PASSED" : "FAILED") << "\n";
    
    // --- Final Verification: Both KoR and Pairing checks must pass ---
    bool valid = kor_ok && pairing_ok;
    if (valid) {
        std::cout << "[VERIFY] Credential verification PASSED.\n";
    } else {
        std::cout << "[VERIFY] Credential verification FAILED.\n";
    }
    
    // --- Clean up temporary elements ---
    element_clear(c_elem);
    element_clear(s1_elem);
    element_clear(s2_elem);
    element_clear(s3_elem);
    element_clear(one);
    element_clear(one_minus_c);
    element_clear(part1);
    element_clear(part2);
    element_clear(part3);
    element_clear(part4);
    element_clear(k_double);
    element_clear(part5);
    element_clear(part6);
    element_clear(part7);
    element_clear(com_double);
    element_clear(c_prime);
    element_clear(pairing_lhs);
    element_clear(pairing_rhs);
    
    // Note: r1p, r2p, r3p and other temporary elements used in proveCredential have already been cleared in that function.
    
    return valid;
}
