#include "provecredential.h"
#include <openssl/sha.h>
#include <sstream>
#include <iomanip>
#include <stdexcept>
#include <iostream>

// Eğer global elementToStringG1 tanımlı değilse, aşağıdaki gibi bir yardımcı fonksiyon ekleyin.
extern std::string elementToStringG1(element_t elem);

// Yardımcı: mpz_t'yi string'e çevirir.
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
    
    // 1) Rastgele r değeri seç (Zr).
    element_t r;
    element_init_Zr(r, params.pairing);
    element_random(r);
    std::cout << "[PROVE] Random r chosen (Zr): " << elementToStringG1(r)
              << " (Note: r is in Zr, not directly human-readable)\n";
    
    // 2) h'' = h^r, burada h aggregate imzadan alınan h'dir.
    element_t h_dbl;
    element_init_G1(h_dbl, params.pairing);
    element_pow_zn(h_dbl, aggSig.h, r);
    std::cout << "[PROVE] h'' computed: " << elementToStringG1(h_dbl) << "\n";
    
    // 3) s'' = s^r * (h'')^r, burada s aggregate imzadan alınan s'dir.
    element_t s_r, h_dbl_r, s_dbl;
    element_init_G1(s_r, params.pairing);
    element_init_G1(h_dbl_r, params.pairing);
    element_init_G1(s_dbl, params.pairing);
    element_pow_zn(s_r, aggSig.s, r);
    element_pow_zn(h_dbl_r, h_dbl, r);
    element_mul(s_dbl, s_r, h_dbl_r);
    std::cout << "[PROVE] s'' computed: " << elementToStringG1(s_dbl) << "\n";
    
    // σ'' = (h'', s'')
    element_init_G1(output.sigmaRnd.h, params.pairing);
    element_set(output.sigmaRnd.h, h_dbl);
    element_init_G1(output.sigmaRnd.s, params.pairing);
    element_set(output.sigmaRnd.s, s_dbl);
    
    // 4) k = α₂ * (β₂)^(DID) * g₂^r
    // mvk.vkm1 = α₂, mvk.vkm2 = β₂.
    // DID'i mpz_t'ye çevir:
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
    element_pow_zn(beta_exp, mvk.vkm2, expElem);
    element_clear(expElem);
    
    // Compute g₂^r
    element_t g2_r;
    element_init_G1(g2_r, params.pairing);
    element_pow_zn(g2_r, params.g2, r);
    
    // k = α₂ * (β₂)^(DID) * g₂^r, where α₂ = mvk.vkm1.
    element_init_G1(output.k, params.pairing);
    element_mul(output.k, mvk.vkm1, beta_exp);
    element_mul(output.k, output.k, g2_r);
    std::cout << "[PROVE] k computed: " << elementToStringG1(output.k) << "\n";
    
    // 5) π_v ← KoR(k)
    // Basitçe k'nin SHA512 hash'ini hesaplayıp proof_v olarak atayalım.
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
    element_clear(r);
    element_clear(h_dbl);
    element_clear(s_r);
    element_clear(h_dbl_r);
    element_clear(s_dbl);
    element_clear(beta_exp);
    element_clear(g2_r);
    mpz_clear(didInt);
    
    // Debug bilgilerini toplayalım.
    std::ostringstream dbg;
    dbg << "h'' = " << elementToStringG1(output.sigmaRnd.h) << "\n";
    dbg << "s'' = " << elementToStringG1(output.sigmaRnd.s) << "\n";
    dbg << "k   = " << elementToStringG1(output.k) << "\n";
    output.sigmaRnd.debug_info = dbg.str();
    
    return output;
}
