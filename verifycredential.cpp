#include "verifycredential.h"
#include <openssl/sha.h>
#include <sstream>
#include <iomanip>
#include <stdexcept>
#include <iostream>
#include <vector>

// Extern: elementToStringG1 now accepts a const element_t parameter.
extern std::string elementToStringG1(const element_t elem);

// Helper: Convert an mpz_t value to a std::string.
static std::string mpzToString(const mpz_t value) {
    char* c_str = mpz_get_str(nullptr, 10, value);
    std::string str(c_str);
    free(c_str);
    return str;
}

// Helper: Parse the KoR tuple from a string (expected 4 tokens separated by spaces).
void parseKoRTuple(const std::string &tupleStr, std::string &c_str, std::string &s1_str, std::string &s2_str, std::string &s3_str) {
    std::istringstream iss(tupleStr);
    if (!(iss >> c_str >> s1_str >> s2_str >> s3_str)) {
        throw std::runtime_error("verifyCredential: Failed to parse KoR tuple from proof_v");
    }
}

// Helper: Convert a hexadecimal string to an mpz_t.
void hexStringToMpz(mpz_t result, const std::string &hexStr) {
    if (mpz_set_str(result, hexStr.c_str(), 16) != 0) {
        throw std::runtime_error("verifyCredential: Failed to convert hex string to mpz");
    }
}

bool verifyCredential(
    TIACParams &params,
    ProveCredentialOutput &pOut,
    MasterVerKey &mvk,
    AggregateSignature &aggSig,
    const element_t com  // The commitment computed in the prepare phase
) {
    std::cout << "[VERIFY] Starting credential verification.\n";
    
    // --- Step A: Parse KoR tuple from pOut.proof_v ---
    std::string c_hex, s1_hex, s2_hex, s3_hex;
    parseKoRTuple(pOut.proof_v, c_hex, s1_hex, s2_hex, s3_hex);
    std::cout << "[VERIFY] Parsed KoR tuple: c = " << c_hex 
              << ", s1 = " << s1_hex 
              << ", s2 = " << s2_hex 
              << ", s3 = " << s3_hex << "\n";
    
    // Convert these hex strings into elements in Zr.
    element_t c_elem, s1_elem, s2_elem, s3_elem;
    element_init_Zr(c_elem, params.pairing);
    element_init_Zr(s1_elem, params.pairing);
    element_init_Zr(s2_elem, params.pairing);
    element_init_Zr(s3_elem, params.pairing);
    
    mpz_t temp_mpz;
    mpz_init(temp_mpz);
    hexStringToMpz(temp_mpz, c_hex);
    element_set_mpz(c_elem, temp_mpz);
    hexStringToMpz(temp_mpz, s1_hex);
    element_set_mpz(s1_elem, temp_mpz);
    hexStringToMpz(temp_mpz, s2_hex);
    element_set_mpz(s2_elem, temp_mpz);
    hexStringToMpz(temp_mpz, s3_hex);
    element_set_mpz(s3_elem, temp_mpz);
    mpz_clear(temp_mpz);
    
    std::cout << "[VERIFY] KoR elements (as Zr): c = " << elementToStringG1(c_elem)
              << ", s1 = " << elementToStringG1(s1_elem)
              << ", s2 = " << elementToStringG1(s2_elem)
              << ", s3 = " << elementToStringG1(s3_elem) << "\n";
    
    // --- Step B: Compute k″ = g1^(s1) · (α2)^(1−c) · k · (β2)^(s2) ---
    element_t part1, part2, part3, part4, k_double;
    element_init_G1(part1, params.pairing);
    element_init_G1(part2, params.pairing);
    element_init_G1(part3, params.pairing);
    element_init_G1(part4, params.pairing);
    element_init_G1(k_double, params.pairing);
    
    // part1 = g1^(s1)
    element_pow_zn(part1, params.g1, s1_elem);
    
    // one_minus_c = 1 - c in Zr
    element_t one, one_minus_c;
    element_init_Zr(one, params.pairing);
    element_init_Zr(one_minus_c, params.pairing);
    element_set1(one);
    element_sub(one_minus_c, one, c_elem);
    
    // part2 = (mvk.alpha2)^(1 - c)
    element_pow_zn(part2, mvk.alpha2, one_minus_c);
    
    // part3 = k (from pOut)
    element_set(part3, pOut.k);
    
    // part4 = (mvk.beta2)^(s2)
    element_pow_zn(part4, mvk.beta2, s2_elem);
    
    // k_double = part1 * part2 * part3 * part4
    element_mul(k_double, part1, part2);
    element_mul(k_double, k_double, part3);
    element_mul(k_double, k_double, part4);
    
    std::cout << "[VERIFY] k_double computed: " << elementToStringG1(k_double) << "\n";
    
    element_clear(part1);
    element_clear(part2);
    element_clear(part3);
    element_clear(part4);
    element_clear(one);
    element_clear(one_minus_c);
    
    // --- Step C: Compute com″ = g1^(s3) · h^(s2) · com^(c) ---
    element_t part5, part6, part7, com_double;
    element_init_G1(part5, params.pairing);
    element_init_G1(part6, params.pairing);
    element_init_G1(part7, params.pairing);
    element_init_G1(com_double, params.pairing);
    
    // part5 = g1^(s3)
    element_pow_zn(part5, params.g1, s3_elem);
    
    // part6 = h^(s2) where h is pOut.sigmaRnd.h (i.e. h'')
    element_pow_zn(part6, pOut.sigmaRnd.h, s2_elem);
    
    // part7 = com^(c), using the provided com (from prepare phase)
    element_pow_zn(part7, com, c_elem);
    
    // com_double = part5 * part6 * part7
    element_mul(com_double, part5, part6);
    element_mul(com_double, com_double, part7);
    
    std::cout << "[VERIFY] com_double computed: " << elementToStringG1(com_double) << "\n";
    
    element_clear(part5);
    element_clear(part6);
    element_clear(part7);
    
    // --- Step D: Compute c′ = Hash( g1 || g2 || h || com || com″ || k || k″ ) ---
    std::ostringstream hashOSS;
    hashOSS << elementToStringG1(params.g1)
            << elementToStringG1(params.g2)
            << elementToStringG1(pOut.sigmaRnd.h)
            << elementToStringG1(com)
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
    
    // Convert c_prime_str to an element in Zr (c′)
    mpz_t c_prime_mpz;
    mpz_init(c_prime_mpz);
    if(mpz_set_str(c_prime_mpz, c_prime_str.c_str(), 16) != 0)
        throw std::runtime_error("verifyCredential: Error converting hash to mpz");
    mpz_mod(c_prime_mpz, c_prime_mpz, params.prime_order);
    element_t c_prime_elem;
    element_init_Zr(c_prime_elem, params.pairing);
    element_set_mpz(c_prime_elem, c_prime_mpz);
    mpz_clear(c_prime_mpz);
    std::cout << "[VERIFY] c' (as element): " << elementToStringG1(c_prime_elem) << "\n";
    
    // --- Step E: Compare c′ with c (from the KoR tuple) ---
    bool kor_check = (element_cmp(c_prime_elem, c_elem) == 0);
    if (!kor_check) {
        std::cout << "[VERIFY] KoR check FAILED: computed c' does not equal c from tuple.\n";
    } else {
        std::cout << "[VERIFY] KoR check PASSED: computed c' equals c from tuple.\n";
    }
    
    element_clear(c_elem);
    element_clear(s1_elem);
    element_clear(s2_elem);
    element_clear(s3_elem);
    element_clear(k_double);
    element_clear(com_double);
    element_clear(c_prime_elem);
    
    // --- Step F: Pairing Check (Algorithm 18) ---
    element_t pairing_lhs, pairing_rhs;
    element_init_GT(pairing_lhs, params.pairing);
    element_init_GT(pairing_rhs, params.pairing);
    pairing_apply(pairing_lhs, pOut.sigmaRnd.h, pOut.k, params.pairing);
    pairing_apply(pairing_rhs, pOut.sigmaRnd.s, params.g2, params.pairing);
    std::cout << "[VERIFY] Pairing LHS = " << elementToStringG1(pairing_lhs) << "\n";
    std::cout << "[VERIFY] Pairing RHS = " << elementToStringG1(pairing_rhs) << "\n";
    bool pairing_check = (element_cmp(pairing_lhs, pairing_rhs) == 0);
    if (pairing_check) {
        std::cout << "[VERIFY] Pairing check PASSED: e(h'', k) == e(s'', g2)\n";
    } else {
        std::cout << "[VERIFY] Pairing check FAILED: e(h'', k) != e(s'', g2)\n";
    }
    element_clear(pairing_lhs);
    element_clear(pairing_rhs);
    
    // --- Final Decision ---
    bool valid = kor_check && pairing_check;
    if (valid) {
        std::cout << "[VERIFY] Credential verification PASSED.\n";
    } else {
        std::cout << "[VERIFY] Credential verification FAILED.\n";
    }
    
    return valid;
}
