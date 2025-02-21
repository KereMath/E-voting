#include "blindsign.h"
#include "common_utils.h"
#include <iostream> // cerr için
bool checkKoR(TIACParams &params, element_t com, element_t comi, element_t h, Proof &pi_s) {
    element_t comp_i, comp;
    element_init_G1(comp_i, params.pairing);
    element_init_G1(comp, params.pairing);
    
    // com′_i ← g1^(s1) · h1^(s2) . comi^c
    {
        element_t t1, t2, t3;
        element_init_G1(t1, params.pairing);
        element_init_G1(t2, params.pairing);
        element_init_G1(t3, params.pairing);
        element_pow_zn(t1, params.g1, pi_s.s1);
        element_pow_zn(t2, params.h1, pi_s.s2);
        element_pow_zn(t3, comi, pi_s.c);
        element_mul(comp_i, t1, t2);
        element_mul(comp_i, comp_i, t3);
        element_clear(t1); element_clear(t2); element_clear(t3);
    }
    
    //  com′ ← g1^(s3) · h^(s2) * com^(c)
    {
        element_t t1, t2, t3;
        element_init_G1(t1, params.pairing);
        element_init_G1(t2, params.pairing);
        element_init_G1(t3, params.pairing);
        element_pow_zn(t1, params.g1, pi_s.s3);
        element_pow_zn(t2, h, pi_s.s2);
        element_pow_zn(t3, com, pi_s.c);
        element_mul(comp, t1, t2);
        element_mul(comp, comp, t3);
        element_clear(t1); element_clear(t2); element_clear(t3);
    }
    
    //c' ← Hash(g1, h, h1, com, com′, comi, com′_i)
    std::vector<std::string> hashData;
    hashData.push_back(canonicalElementToHex(params.g1));
    hashData.push_back(canonicalElementToHex(h));
    hashData.push_back(canonicalElementToHex(params.h1));
    hashData.push_back(canonicalElementToHex(com));
    hashData.push_back(canonicalElementToHex(comp));
    hashData.push_back(canonicalElementToHex(comi));
    hashData.push_back(canonicalElementToHex(comp_i));
    element_t c_prime;
    element_init_Zr(c_prime, params.pairing);
    hashVectorToZr(hashData, params, c_prime);
    
    bool valid = (element_cmp(c_prime, pi_s.c) == 0);
    
    element_clear(comp_i);
    element_clear(comp);
    element_clear(c_prime);
    return valid;
}
BlindSignature blindSign(TIACParams& params, BlindSignOutput& blindOut, element_t xm, element_t ym) {
    BlindSignature sig;

    // İspatın doğrulanması (Algoritma 6)
    bool korOk = checkKoR(params, blindOut.com, blindOut.comi, blindOut.h, blindOut.pi_s);

    // Hash(comi) kontrolü (Algoritma 12, adım 1)
    element_t h_check;
    element_init_G1(h_check, params.pairing);
    hashToG1(canonicalElementToHex(blindOut.comi), params, h_check);
    bool hashOk = (element_cmp(h_check, blindOut.h) == 0);
    element_clear(h_check);

    if (!korOk || !hashOk) {
        std::cerr << "Warning: Blind Sign Check Failed: KoR proof is invalid or Hash(comi) != h." << std::endl;
        // Simülasyon yerine hata döndürüyoruz:
        element_init_G1(sig.h, params.pairing); //h ve cm yi boş yarat
        element_init_G1(sig.cm, params.pairing);
        return sig;  // Boş bir imza döndür.  Veya exception fırlat.
    }

    // Algoritma 12, Adım 4: cm = h^(xm) * com^(ym)
    element_init_G1(sig.h, params.pairing);
    element_set(sig.h, blindOut.h);  // h değerini kopyala
    element_init_G1(sig.cm, params.pairing);

    element_t temp1, temp2;
    element_init_G1(temp1, params.pairing);
    element_init_G1(temp2, params.pairing);

    element_pow_zn(temp1, blindOut.h, xm);     // h^xm
    element_pow_zn(temp2, blindOut.com, ym); // com^ym  <- DÜZELTİLDİ: com kullanılıyor
    element_mul(sig.cm, temp1, temp2);       // cm = h^xm * com^ym

    element_clear(temp1);
    element_clear(temp2);

    return sig;
}