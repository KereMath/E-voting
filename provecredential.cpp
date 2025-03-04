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
    const std::string &didStr
) {
    ProveCredentialOutput output;
    
    // 1) Rastgele r1 ve r2 değerleri seç (her ikisi de Zr'de)
    element_t r1, r2;
    element_init_Zr(r1, params.pairing);
    element_init_Zr(r2, params.pairing);
    element_random(r1);
    element_random(r2);
    std::cout << "[PROVE] Random r1 chosen (Zr, for h''): " << elementToStringG1(r1)
              << "\n[PROVE] Random r2 chosen (Zr, for s'' and k exponent): " << elementToStringG1(r2) << "\n";
    
    // 2) h'' = h^(r1); h, aggregate imzadan alınan h'dir.
    element_t h_dbl;
    element_init_G1(h_dbl, params.pairing);
    element_pow_zn(h_dbl, aggSig.h, r1);
    std::cout << "[PROVE] h'' computed: " << elementToStringG1(h_dbl) << "\n";
    
    // 3) s'' = s^(r1) * (h'')^(r2); s, aggregate imzadan alınan s'dir.
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
    // mvk.alpha2 = α₂, mvk.beta2 = β₂.
    mpz_t didInt;
    mpz_init(didInt);
    if(mpz_set_str(didInt, didStr.c_str(), 16) != 0)
        throw std::runtime_error("proveCredential: Invalid DID hex string");
    mpz_mod(didInt, didInt, params.prime_order);
    std::cout << "[PROVE] DID (mpz): " << mpzToString(didInt) << "\n";
    
    element_t beta_exp;
    element_init_G1(beta_exp, params.pairing);
    element_t expElem;
    element_init_Zr(expElem, params.pairing);
    element_set_mpz(expElem, didInt);
    element_pow_zn(beta_exp, mvk.beta2, expElem);
    element_clear(expElem);
    
    element_t g2_r2;
    element_init_G1(g2_r2, params.pairing);
    element_pow_zn(g2_r2, params.g2, r2);
    
    element_init_G1(output.k, params.pairing);
    element_mul(output.k, mvk.alpha2, beta_exp);
    element_mul(output.k, output.k, g2_r2);
    std::cout << "[PROVE] k computed: " << elementToStringG1(output.k) << "\n";
    
    // 5) π_v ← SHA512 hash(k)
    unsigned char digest[SHA512_DIGEST_LENGTH];
    std::string kStr = elementToStringG1(output.k);
    SHA512(reinterpret_cast<const unsigned char*>(kStr.data()), kStr.size(), digest);
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (int i = 0; i < SHA512_DIGEST_LENGTH; i++) {
        oss << std::setw(2) << (int)digest[i];
    }
    output.proof_v = oss.str();
    std::cout << "[PROVE] Proof (π_v) computed as hash(k): " << output.proof_v << "\n";
    
    // Temizleme
    element_clear(r1);
    element_clear(r2);
    element_clear(h_dbl);
    element_clear(s_r1);
    element_clear(h_dbl_r2);
    element_clear(s_dbl);
    element_clear(beta_exp);
    element_clear(g2_r2);
    mpz_clear(didInt);
    
    // Debug bilgileri
    std::ostringstream dbg;
    dbg << "h'' = " << elementToStringG1(output.sigmaRnd.h) << "\n";
    dbg << "s'' = " << elementToStringG1(output.sigmaRnd.s) << "\n";
    dbg << "k   = " << elementToStringG1(output.k) << "\n";
    output.sigmaRnd.debug_info = dbg.str();
    
    return output;
}
