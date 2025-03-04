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
    const mpz_t o   // prepareBlindSign aşamasından alınan "o" değeri
) {
    ProveCredentialOutput output;
    std::cout << "\n[PROVE] ===== ProveCredential Phase START =====\n";
    
    // --- Adım 1: Rastgele Üslerin Seçilmesi ---
    element_t rp, r;
    element_init_Zr(rp, params.pairing);
    element_init_Zr(r, params.pairing);
    element_random(rp);
    element_random(r);
    std::cout << "[PROVE] Random r' chosen (for h''): " << elementToStringG1(rp) << "\n";
    std::cout << "[PROVE] Random r chosen (for exponent in s'' and k): " << elementToStringG1(r) << "\n";
    
    // --- Adım 2: h'' = h^(r') ---
    element_t h_dbl;
    element_init_G1(h_dbl, params.pairing);
    element_pow_zn(h_dbl, aggSig.h, rp);
    std::cout << "[PROVE] h'' computed: " << elementToStringG1(h_dbl) << "\n";
    
    // --- Adım 3: s'' = s^(r') * (h'')^(r) ---
    element_t s_rp, h_dbl_r, s_dbl;
    element_init_G1(s_rp, params.pairing);
    element_init_G1(h_dbl_r, params.pairing);
    element_init_G1(s_dbl, params.pairing);
    element_pow_zn(s_rp, aggSig.s, rp);
    element_pow_zn(h_dbl_r, h_dbl, r);
    element_mul(s_dbl, s_rp, h_dbl_r);
    std::cout << "[PROVE] s'' computed: " << elementToStringG1(s_dbl) << "\n";
    
    // --- σRnd = (h'', s'') ---
    element_init_G1(output.sigmaRnd.h, params.pairing);
    element_set(output.sigmaRnd.h, h_dbl);
    element_init_G1(output.sigmaRnd.s, params.pairing);
    element_set(output.sigmaRnd.s, s_dbl);
    
    // --- Adım 4: k = α₂ * (β₂)^(DID) * g₂^(r) ---
    // DID'i hex string'den Zₚ'ye çevir.
    mpz_t didInt;
    mpz_init(didInt);
    if(mpz_set_str(didInt, didStr.c_str(), 16) != 0)
        throw std::runtime_error("proveCredential: Invalid DID hex string");
    mpz_mod(didInt, didInt, params.prime_order);
    std::cout << "[PROVE] DID (mpz) computed: " << mpzToString(didInt) << "\n";
    
    // Print: kullanılan "o" değeri (prepare aşamasından)
    std::cout << "[PROVE] Value of o (from prepare phase): " << mpzToString(o) << "\n";
    
    // β₂'nin üssü: (β₂)^(DID)
    element_t beta_exp;
    element_init_G1(beta_exp, params.pairing);
    element_t expElem;
    element_init_Zr(expElem, params.pairing);
    element_set_mpz(expElem, didInt);
    element_pow_zn(beta_exp, mvk.beta2, expElem);
    element_clear(expElem);
    
    // g₂^(r)
    element_t g2_r;
    element_init_G1(g2_r, params.pairing);
    element_pow_zn(g2_r, params.g2, r);
    
    element_init_G1(output.k, params.pairing);
    // k = α₂ * (β₂)^(DID) * g₂^(r)
    element_mul(output.k, mvk.alpha2, beta_exp);
    element_mul(output.k, output.k, g2_r);
    std::cout << "[PROVE] k computed: " << elementToStringG1(output.k) << "\n";
    
    // --- Adım 5: KoR İspatı (Algoritma 16) ---
    // Rastgele r₁', r₂', r₃' seç
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
    
    // k' = g₁^(r1') · α₂ · (β₂)^(r2')
    element_t k_prime;
    element_init_G1(k_prime, params.pairing);
    {
        element_t temp;
        element_init_G1(temp, params.pairing);
        element_pow_zn(temp, params.g1, r1p);
        element_set(k_prime, temp);
        element_mul(k_prime, k_prime, mvk.alpha2);
        element_pow_zn(temp, mvk.beta2, r2p);
        element_mul(k_prime, k_prime, temp);
        std::cout << "[PROVE] k' computed: " << elementToStringG1(k_prime) << "\n";
        element_clear(temp);
    }
    
    // com' = g₁^(r3') · (h'')^(r2')
    element_t com_prime;
    element_init_G1(com_prime, params.pairing);
    {
        element_t temp;
        element_init_G1(temp, params.pairing);
        element_pow_zn(temp, params.g1, r3p);
        element_set(com_prime, temp);
        element_pow_zn(temp, output.sigmaRnd.h, r2p);
        element_mul(com_prime, com_prime, temp);
        std::cout << "[PROVE] com' computed: " << elementToStringG1(com_prime) << "\n";
        element_clear(temp);
    }
    
    // com: Prepare aşamasında üretilmeyen bir değer, burada identity (1) kabul ediliyor.
    element_t com_identity;
    element_init_G1(com_identity, params.pairing);
    element_set1(com_identity);
    
    // Compute hash: c = Hash(g₁, g₂, h'', com, com', k, k')
    std::vector<std::string> hashInputs;
    hashInputs.push_back(elementToStringG1(params.g1));
    hashInputs.push_back(elementToStringG1(params.g2));
    hashInputs.push_back(elementToStringG1(output.sigmaRnd.h));
    hashInputs.push_back(elementToStringG1(com_identity));
    hashInputs.push_back(elementToStringG1(com_prime));
    hashInputs.push_back(elementToStringG1(output.k));
    hashInputs.push_back(elementToStringG1(k_prime));
    
    std::ostringstream oss;
    for (const auto &s : hashInputs)
        oss << s;
    std::string concatStr = oss.str();
    unsigned char digest[SHA512_DIGEST_LENGTH];
    SHA512(reinterpret_cast<const unsigned char*>(concatStr.data()), concatStr.size(), digest);
    mpz_t tmp;
    mpz_init(tmp);
    mpz_import(tmp, SHA512_DIGEST_LENGTH, 1, 1, 0, 0, digest);
    mpz_mod(tmp, tmp, params.prime_order);
    element_t c_elem;
    element_init_Zr(c_elem, params.pairing);
    element_set_mpz(c_elem, tmp);
    mpz_clear(tmp);
    std::cout << "[PROVE] c computed (from hash): " << elementToStringG1(c_elem) << "\n";
    
    // Compute s₁ = r1' − c·(r')
    element_t s1_elem, s2_elem, s3_elem;
    element_init_Zr(s1_elem, params.pairing);
    element_init_Zr(s2_elem, params.pairing);
    element_init_Zr(s3_elem, params.pairing);
    
    element_mul(s1_elem, c_elem, rp);
    element_sub(s1_elem, r1p, s1_elem);
    std::cout << "[PROVE] s1 computed: " << elementToStringG1(s1_elem) << "\n";
    
    // Compute s₂ = r2' − c·(DID)
    element_t did_elem;
    element_init_Zr(did_elem, params.pairing);
    element_set_mpz(did_elem, didInt);  // didInt was computed earlier
    element_mul(s2_elem, c_elem, did_elem);
    element_sub(s2_elem, r2p, s2_elem);
    std::cout << "[PROVE] s2 computed: " << elementToStringG1(s2_elem) << "\n";
    
    // Compute s₃ = r3' − c·o ; burada o kullanılıyorsa (aksi halde 0 kabul edilir)
    element_t s3_temp;
    element_init_Zr(s3_temp, params.pairing);
    element_set(s3_temp, o);  // o, prepare aşamasından gelen o değeri
    element_mul(s3_elem, c_elem, s3_temp);
    element_sub(s3_elem, r3p, s3_elem);
    std::cout << "[PROVE] s3 computed: " << elementToStringG1(s3_elem) << "\n";
    
    // Serialize KoR tuple: π_v = (c, s1, s2, s3)
    std::ostringstream proofStream;
    proofStream << elementToStringG1(c_elem) << " "
                << elementToStringG1(s1_elem) << " "
                << elementToStringG1(s2_elem) << " "
                << elementToStringG1(s3_elem);
    output.proof_v = proofStream.str();
    std::cout << "[PROVE] π_v computed (KoR tuple): " << output.proof_v << "\n";
    
    // --- Temizleme ---
    element_clear(rp);
    element_clear(r);
    element_clear(h_dbl);
    element_clear(s_rp);
    element_clear(h_dbl_r);
    element_clear(s_dbl);
    element_clear(beta_exp);
    element_clear(g2_r);
    element_clear(r1p);
    element_clear(r2p);
    element_clear(r3p);
    element_clear(c_elem);
    element_clear(s1_elem);
    element_clear(s2_elem);
    element_clear(s3_elem);
    element_clear(did_elem);
    element_clear(com_identity);
    element_clear(com_prime);
    element_clear(k_prime);
    mpz_clear(didInt);
    
    output.sigmaRnd.debug_info = "h'' = " + elementToStringG1(output.sigmaRnd.h) + "\n" +
                                  "s'' = " + elementToStringG1(output.sigmaRnd.s) + "\n" +
                                  "k   = " + elementToStringG1(output.k) + "\n" +
                                  "π_v = " + output.proof_v + "\n";
    
    std::cout << "[PROVE] ===== ProveCredential Phase END =====\n";
    return output;
}
