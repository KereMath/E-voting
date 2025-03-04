#include "provecredential.h"
#include <openssl/sha.h>
#include <sstream>
#include <iomanip>
#include <stdexcept>
#include <iostream>

// Dışarıdan tanımlı: elementToStringG1 artık const parametre alır.
extern std::string elementToStringG1(const element_t elem);

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
    const mpz_t o   // o değeri (prepare aşamasından gelen)
) {
    ProveCredentialOutput output;
    
    // 1) Rastgele r1 ve r2 değerleri seç (her ikisi de Zr'de)
    element_t r1, r2;
    element_init_Zr(r1, params.pairing);
    element_init_Zr(r2, params.pairing);
    element_random(r1);
    element_random(r2);
    std::cout << "[PROVE] Random r1 chosen (for h''): " << elementToStringG1(r1) << "\n";
    std::cout << "[PROVE] Random r2 chosen (for exponent in k and s''): " << elementToStringG1(r2) << "\n";
    
    // 2) h'' = h^(r1); (h, aggregate imzadan alınan h)
    element_t h_dbl;
    element_init_G1(h_dbl, params.pairing);
    element_pow_zn(h_dbl, aggSig.h, r1);
    std::cout << "[PROVE] h'' computed: " << elementToStringG1(h_dbl) << "\n";
    
    // 3) s'' = s^(r1) * (h'')^(r2); (s, aggregate imzadan alınan s)
    element_t s_r1, h_dbl_r2, s_dbl;
    element_init_G1(s_r1, params.pairing);
    element_init_G1(h_dbl_r2, params.pairing);
    element_init_G1(s_dbl, params.pairing);
    element_pow_zn(s_r1, aggSig.s, r1);
    element_pow_zn(h_dbl_r2, h_dbl, r2);
    element_mul(s_dbl, s_r1, h_dbl_r2);
    std::cout << "[PROVE] s'' computed: " << elementToStringG1(s_dbl) << "\n";
    
    // σRnd = (h'', s'')
    element_init_G1(output.sigmaRnd.h, params.pairing);
    element_set(output.sigmaRnd.h, h_dbl);
    element_init_G1(output.sigmaRnd.s, params.pairing);
    element_set(output.sigmaRnd.s, s_dbl);
    
    // 4) k = α₂ * (β₂)^(DID) * g₂^(r2)
    // DID string'ini mpz_t'ye çevir
    mpz_t didInt;
    mpz_init(didInt);
    if (mpz_set_str(didInt, didStr.c_str(), 16) != 0)
        throw std::runtime_error("proveCredential: Invalid DID hex string");
    mpz_mod(didInt, didInt, params.prime_order);
    std::cout << "[PROVE] DID (mpz): " << mpzToString(didInt) << "\n";
    
    // Print the used o value
    std::cout << "[PROVE DEBUG] o = " << mpzToString(o) << "\n";
    
    // Compute (β₂)^(DID)
    element_t beta_exp;
    element_init_G1(beta_exp, params.pairing);
    element_t expElem;
    element_init_Zr(expElem, params.pairing);
    element_set_mpz(expElem, didInt);
    element_pow_zn(beta_exp, mvk.beta2, expElem);
    element_clear(expElem);
    
    // Compute g₂^(r2)
    element_t g2_r2;
    element_init_G1(g2_r2, params.pairing);
    element_pow_zn(g2_r2, params.g2, r2);
    
    // k = α₂ · (β₂)^(DID) · g₂^(r2)
    element_init_G1(output.k, params.pairing);
    element_mul(output.k, mvk.alpha2, beta_exp);
    element_mul(output.k, output.k, g2_r2);
    std::cout << "[PROVE] k computed: " << elementToStringG1(output.k) << "\n";
    
    // 5) KoR (Knowledge of Representation) Tuple Computation (Alg. 16)
    //    Uygulamada, tuple (c, s1, s2, s3) üretiliyor.
    //    (Bu kısım, algoritmanın örnek implementasyonu olup, hash üzerinden hesaplanmaktadır.)
    element_t r1p, r2p, r3p;
    element_init_Zr(r1p, params.pairing);
    element_init_Zr(r2p, params.pairing);
    element_init_Zr(r3p, params.pairing);
    element_random(r1p);
    element_random(r2p);
    element_random(r3p);
    std::cout << "[PROVE] Random r1' chosen: " << elementToStringG1(r1p) << "\n";
    std::cout << "[PROVE] Random r2' chosen: " << elementToStringG1(r2p) << "\n";
    std::cout << "[PROVE] Random r3' chosen: " << elementToStringG1(r3p) << "\n";
    
    // k' = g1^(r1') · mvk.alpha2 · (mvk.beta2)^(r2')
    element_t k_prime;
    element_init_G1(k_prime, params.pairing);
    element_t g1_r1p, beta2_r2p;
    element_init_G1(g1_r1p, params.pairing);
    element_init_G1(beta2_r2p, params.pairing);
    element_pow_zn(g1_r1p, params.g1, r1p);
    element_pow_zn(beta2_r2p, mvk.beta2, r2p);
    element_mul(k_prime, g1_r1p, mvk.alpha2);
    element_mul(k_prime, k_prime, beta2_r2p);
    
    // com' = g1^(r3') · (h'')^(r2')
    element_t com_prime;
    element_init_G1(com_prime, params.pairing);
    element_t g1_r3p, h_r2p;
    element_init_G1(g1_r3p, params.pairing);
    element_init_G1(h_r2p, params.pairing);
    element_pow_zn(g1_r3p, params.g1, r3p);
    element_pow_zn(h_r2p, h_dbl, r2p);
    element_mul(com_prime, g1_r3p, h_r2p);
    
    // c = Hash(g1, g2, h'', com, com', k, k')
    std::ostringstream hashOSS;
    hashOSS << elementToStringG1(params.g1)
            << elementToStringG1(params.g2)
            << elementToStringG1(h_dbl)
            << elementToStringG1(aggSig.s)  // Using aggregate s as com (or identity if available)
            << elementToStringG1(com_prime)
            << elementToStringG1(output.k)
            << elementToStringG1(k_prime);
    std::string hashInput = hashOSS.str();
    unsigned char hashDigest[SHA512_DIGEST_LENGTH];
    SHA512(reinterpret_cast<const unsigned char*>(hashInput.data()), hashInput.size(), hashDigest);
    std::ostringstream hashFinalOSS;
    hashFinalOSS << std::hex << std::setfill('0');
    for (int i = 0; i < SHA512_DIGEST_LENGTH; i++) {
        hashFinalOSS << std::setw(2) << (int)hashDigest[i];
    }
    std::string c_str = hashFinalOSS.str();
    
    mpz_t c_mpz;
    mpz_init(c_mpz);
    if(mpz_set_str(c_mpz, c_str.c_str(), 16) != 0)
        throw std::runtime_error("proveCredential: Error converting hash to mpz");
    mpz_mod(c_mpz, c_mpz, params.prime_order);
    element_t c_elem;
    element_init_Zr(c_elem, params.pairing);
    element_set_mpz(c_elem, c_mpz);
    mpz_clear(c_mpz);
    std::cout << "[PROVE] c computed from hash: " << elementToStringG1(c_elem) << "\n";
    
    // 5a) s1 = r1' − c·r1
    element_t s1, s2, s3;
    element_init_Zr(s1, params.pairing);
    element_init_Zr(s2, params.pairing);
    element_init_Zr(s3, params.pairing);
    {
        element_t temp;
        element_init_Zr(temp, params.pairing);
        element_mul(temp, c_elem, r1);
        element_sub(s1, r1p, temp);
        element_clear(temp);
    }
    std::cout << "[PROVE] s1 computed: " << elementToStringG1(s1) << "\n";
    
    // 5b) s2 = r2' − c·(didInt)
    element_t temp2;
    element_init_Zr(temp2, params.pairing);
    element_mul(temp2, c_elem, expElem); // Note: expElem was used earlier; reinitialize it.
    element_init_Zr(expElem, params.pairing);
    element_set_mpz(expElem, didInt);
    element_mul(temp2, c_elem, expElem);
    element_sub(s2, r2p, temp2);
    element_clear(temp2);
    std::cout << "[PROVE] s2 computed: " << elementToStringG1(s2) << "\n";
    
    // 5c) s3 = r3' − c·o
    // o is given as a (possibly const) mpz_t; copy it to a temporary non-const mpz_t.
    mpz_t tempO;
    mpz_init(tempO);
    mpz_set(tempO, o);
    element_t o_elem;
    element_init_Zr(o_elem, params.pairing);
    element_set_mpz(o_elem, tempO);
    mpz_clear(tempO);
    
    element_t temp3;
    element_init_Zr(temp3, params.pairing);
    element_mul(temp3, c_elem, o_elem);
    element_sub(s3, r3p, temp3);
    element_clear(temp3);
    std::cout << "[PROVE] s3 computed: " << elementToStringG1(s3) << "\n";
    
    // Construct the KoR tuple: π_v = (c, s1, s2, s3)
    std::ostringstream korOSS;
    korOSS << elementToStringG1(c_elem) << " "
           << elementToStringG1(s1) << " "
           << elementToStringG1(s2) << " "
           << elementToStringG1(s3);
    std::string kor_tuple = korOSS.str();
    std::cout << "[PROVE] KoR tuple computed: " << kor_tuple << "\n";
    
    // Set the proof in output to the tuple
    output.proof_v = kor_tuple;
    std::cout << "[PROVE] Final Proof (π_v): " << output.proof_v << "\n";
    
    // Clean up temporary elements for KoR computation
    element_clear(r1p);
    element_clear(r2p);
    element_clear(r3p);
    element_clear(k_prime);
    element_clear(g1_r1p);
    element_clear(beta2_r2p);
    element_clear(g1_r3p);
    element_clear(h_r2p);
    element_clear(com_prime);
    element_clear(c_elem);
    element_clear(s1);
    element_clear(s2);
    element_clear(s3);
    element_clear(expElem);
    element_clear(o_elem);
    
    // Debug information
    std::ostringstream dbg;
    dbg << "h'' = " << elementToStringG1(output.sigmaRnd.h) << "\n";
    dbg << "s'' = " << elementToStringG1(output.sigmaRnd.s) << "\n";
    dbg << "k   = " << elementToStringG1(output.k) << "\n";
    dbg << "KoR tuple = " << output.proof_v << "\n";
    output.sigmaRnd.debug_info = dbg.str();
    
    // Clear temporary variables
    element_clear(r1);
    element_clear(r2);
    element_clear(h_dbl);
    element_clear(s_r1);
    element_clear(h_dbl_r2);
    element_clear(s_dbl);
    element_clear(beta_exp);
    element_clear(g2_r2);
    mpz_clear(didInt);
    
    return output;
}
