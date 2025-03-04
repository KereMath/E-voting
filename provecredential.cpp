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

// Helper: Verilen elementlerin string gösterimlerini birleştirip SHA512 hash'ini hesaplar.
// Çıktı, Zr elemanı olarak hash değeri.
static std::string computeHashFromElements(const std::vector<element_t> &elems, TIACParams &params) {
    std::ostringstream oss;
    for (const auto &e : elems) {
        oss << elementToStringG1(e);
    }
    std::string data = oss.str();
    unsigned char digest[SHA512_DIGEST_LENGTH];
    SHA512(reinterpret_cast<const unsigned char*>(data.data()), data.size(), digest);
    mpz_t tmp;
    mpz_init(tmp);
    mpz_import(tmp, SHA512_DIGEST_LENGTH, 1, 1, 0, 0, digest);
    mpz_mod(tmp, tmp, params.prime_order);
    std::string hashStr = mpzToString(tmp);
    mpz_clear(tmp);
    return hashStr;
}

ProveCredentialOutput proveCredential(
    TIACParams &params,
    AggregateSignature &aggSig,
    MasterVerKey &mvk,
    const std::string &didStr
) {
    ProveCredentialOutput output;
    
    std::cout << "\n[PROVE] Starting ProveCredential Phase.\n";
    // --- Alg.15: Imza Kanıtı ---
    // 1) Rastgele r₁ ve r₂ (r₁, r₂ ∈ Zₚ)
    element_t r1, r2;
    element_init_Zr(r1, params.pairing);
    element_init_Zr(r2, params.pairing);
    element_random(r1);
    element_random(r2);
    std::cout << "[PROVE] Random r₁: " << elementToStringG1(r1) << "\n";
    std::cout << "[PROVE] Random r₂: " << elementToStringG1(r2) << "\n";
    
    // 2) h″ ← h^(r₁) ; h is aggSig.h (aggregate imzanın h'si)
    element_t h_dbl;
    element_init_G1(h_dbl, params.pairing);
    element_pow_zn(h_dbl, aggSig.h, r1);
    std::cout << "[PROVE] h'' = h^(r₁): " << elementToStringG1(h_dbl) << "\n";
    
    // 3) s″ ← s^(r₁)  (Basit versiyon; isteğe bağlı (h″)^(r₂) ile de çarpılabilir)
    element_t s_dbl;
    element_init_G1(s_dbl, params.pairing);
    element_pow_zn(s_dbl, aggSig.s, r1);
    std::cout << "[PROVE] s'' = s^(r₁): " << elementToStringG1(s_dbl) << "\n";
    
    // σRnd = (h″, s″)
    element_init_G1(output.sigmaRnd.h, params.pairing);
    element_set(output.sigmaRnd.h, h_dbl);
    element_init_G1(output.sigmaRnd.s, params.pairing);
    element_set(output.sigmaRnd.s, s_dbl);
    
    // 4) k ← α₂ · (β₂)^(DID) · g₂^(r₂)
    // DID: hex string → mpz_t → element in Zr.
    mpz_t didInt;
    mpz_init(didInt);
    if(mpz_set_str(didInt, didStr.c_str(), 16) != 0)
        throw std::runtime_error("proveCredential: Invalid DID hex string");
    mpz_mod(didInt, didInt, params.prime_order);
    std::cout << "[PROVE] DID (mpz): " << mpzToString(didInt) << "\n";
    
    // Compute (β₂)^(DID)
    element_t beta_exp;
    element_init_G1(beta_exp, params.pairing);
    element_t expElem;
    element_init_Zr(expElem, params.pairing);
    element_set_mpz(expElem, didInt);
    element_pow_zn(beta_exp, mvk.beta2, expElem);
    element_clear(expElem);
    
    // Compute g₂^(r₂)
    element_t g2_r;
    element_init_G1(g2_r, params.pairing);
    element_pow_zn(g2_r, params.g2, r2);
    
    // k = α₂ · (β₂)^(DID) · g₂^(r₂)
    element_init_G1(output.k, params.pairing);
    element_mul(output.k, mvk.alpha2, beta_exp);
    element_mul(output.k, output.k, g2_r);
    std::cout << "[PROVE] k computed: " << elementToStringG1(output.k) << "\n";
    
    // --- Alg.16: KoR İspatı ---
    // 1) Rastgele r₁', r₂', r₃' ∈ Zₚ
    element_t r1p, r2p, r3p;
    element_init_Zr(r1p, params.pairing);
    element_init_Zr(r2p, params.pairing);
    element_init_Zr(r3p, params.pairing);
    element_random(r1p);
    element_random(r2p);
    element_random(r3p);
    std::cout << "[PROVE] Random r₁': " << elementToStringG1(r1p) << "\n";
    std::cout << "[PROVE] Random r₂': " << elementToStringG1(r2p) << "\n";
    std::cout << "[PROVE] Random r₃': " << elementToStringG1(r3p) << "\n";
    
    // 2) k' ← g₁^(r1') · α₂ · (β₂)^(r2')
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
    
    // 3) com' ← g₁^(r3') · (h'')^(r2')
    element_t com_prime;
    element_init_G1(com_prime, params.pairing);
    {
        element_t temp;
        element_init_G1(temp, params.pairing);
        element_pow_zn(temp, params.g1, r3p);
        element_set(com_prime, temp);
        element_pow_zn(temp, h_dbl, r2p);
        element_mul(com_prime, com_prime, temp);
        std::cout << "[PROVE] com' computed: " << elementToStringG1(com_prime) << "\n";
        element_clear(temp);
    }
    
    // 4) c ← Hash(g₁, g₂, h'', com, com', k, k')
    // Burada com olarak prepare aşamasından gelen com yoksa, identity (1) kullanılır.
    element_t com;
    element_init_G1(com, params.pairing);
    element_set1(com);
    std::vector<element_t> hashElems;
    // push_back sırasıyla: g1, g2, h'', com, com', k, k'
    hashElems.push_back(params.g1);
    hashElems.push_back(params.g2);
    hashElems.push_back(output.sigmaRnd.h);
    hashElems.push_back(com);
    hashElems.push_back(com_prime);
    hashElems.push_back(output.k);
    hashElems.push_back(k_prime);
    
    std::string c_str = computeHashFromElements(hashElems, params);
    // c_str şimdi c değerinin string gösterimi; 
    // dönüştürüp c_elem olarak Zr elemanına atayalım:
    element_t c_elem;
    element_init_Zr(c_elem, params.pairing);
    {
        mpz_t c_mpz;
        mpz_init(c_mpz);
        if(mpz_set_str(c_mpz, c_str.c_str(), 10) != 0)
            throw std::runtime_error("proveCredential: Failed to set c from hash string");
        element_set_mpz(c_elem, c_mpz);
        mpz_clear(c_mpz);
    }
    std::cout << "[PROVE] c computed (KoR hash) = " << elementToStringG1(c_elem) << "\n";
    
    // 5) Compute KoR proof components:
    // s1 = r1' - c * r1
    // s2 = r2' - c * (DID)   (DID is converted to Zr element)
    // s3 = r3' - c * o       (o: prepare aşamasından; burada o = 0)
    element_t s1_elem, s2_elem, s3_elem;
    element_init_Zr(s1_elem, params.pairing);
    element_init_Zr(s2_elem, params.pairing);
    element_init_Zr(s3_elem, params.pairing);
    
    // s1 = r1p - c * r1
    {
        element_t tmp;
        element_init_Zr(tmp, params.pairing);
        element_mul(tmp, c_elem, r1);
        element_sub(s1_elem, r1p, tmp);
        element_clear(tmp);
    }
    
    // s2 = r2p - c * DID
    {
        element_t did_elem;
        element_init_Zr(did_elem, params.pairing);
        element_set_mpz(did_elem, didInt);
        element_t tmp;
        element_init_Zr(tmp, params.pairing);
        element_mul(tmp, c_elem, did_elem);
        element_sub(s2_elem, r2p, tmp);
        element_clear(tmp);
        element_clear(did_elem);
    }
    
    // s3 = r3p - c * o ; o = 0 ⇒ s3 = r3p.
    element_set(s3_elem, r3p);
    std::cout << "[PROVE] s1 computed: " << elementToStringG1(s1_elem) << "\n";
    std::cout << "[PROVE] s2 computed: " << elementToStringG1(s2_elem) << "\n";
    std::cout << "[PROVE] s3 computed: " << elementToStringG1(s3_elem) << "\n";
    
    // Serialize KoR proof tuple π_v = (c, s1, s2, s3) as a space-separated string.
    std::ostringstream proofStream;
    proofStream << elementToStringG1(c_elem) << " "
                << elementToStringG1(s1_elem) << " "
                << elementToStringG1(s2_elem) << " "
                << elementToStringG1(s3_elem);
    output.proof_v = proofStream.str();
    std::cout << "[PROVE] π_v (KoR proof tuple) = " << output.proof_v << "\n";
    
    // Debug info: Dump all computed values.
    std::ostringstream dbg;
    dbg << "h'' = " << elementToStringG1(output.sigmaRnd.h) << "\n";
    dbg << "s'' = " << elementToStringG1(output.sigmaRnd.s) << "\n";
    dbg << "k   = " << elementToStringG1(output.k) << "\n";
    dbg << "KoR Proof Tuple (c, s1, s2, s3) = " << output.proof_v << "\n";
    output.sigmaRnd.debug_info = dbg.str();
    
    // Clean up temporary elements.
    element_clear(r1); element_clear(r2);
    element_clear(h_dbl); element_clear(s_dbl);
    element_clear(beta_exp); element_clear(g2_r);
    mpz_clear(didInt);
    element_clear(r1p); element_clear(r2p); element_clear(r3p);
    element_clear(c_elem); element_clear(s1_elem); element_clear(s2_elem); element_clear(s3_elem);
    element_clear(com); element_clear(com_prime); element_clear(k_prime);
    
    std::cout << "[PROVE] ProveCredential phase completed.\n";
    return output;
}
