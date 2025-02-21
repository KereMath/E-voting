#include "prepareblindsign.h"
#include "common_utils.h"
#include <pbc/pbc.h>
#include <iostream>
#include <vector>

BlindSignOutput prepareBlindSign(TIACParams& params, const std::string& realID) {
    BlindSignOutput out;

    // Adım 1 ve 2: comi hesaplaması
    element_t o_i;
    element_init_Zr(o_i, params.pairing);
    element_random(o_i);

    element_t DID_elem;
    element_init_Zr(DID_elem, params.pairing);
    // Doğrudan element_set_str kullanıyoruz. Hata kontrolü de ekledik.
    if (element_set_str(DID_elem, realID.c_str(), 10) == -1) {
        std::cerr << "Error: Invalid realID (not a valid Zr element)." << std::endl;
        // Burada uygun bir hata işleme mekanizması eklemelisiniz.
        // Örneğin, exception fırlatabilir veya boş bir BlindSignOutput döndürebilirsiniz.
        element_clear(o_i);
        element_clear(DID_elem);
        return out; // Boş bir obje döndürüyoruz.
    }


    element_init_G1(out.comi, params.pairing);
    element_t temp1, temp2;
    element_init_G1(temp1, params.pairing);
    element_init_G1(temp2, params.pairing);
    element_pow_zn(temp1, params.g1, o_i);
    element_pow_zn(temp2, params.h1, DID_elem);
    element_mul(out.comi, temp1, temp2);
    element_clear(temp1);
    element_clear(temp2);


    // Adım 3: h ← Hash(comi)
    std::string comiHex = canonicalElementToHex(out.comi);
    hashToG1(comiHex, params, out.h);


    // Adım 4 ve 5: com hesaplaması
    element_t o;
    element_init_Zr(o, params.pairing);
    element_random(o);

    element_init_G1(out.com, params.pairing);
    element_pow_zn(temp1, params.g1, o);  // temp1 yeniden kullanılıyor
    element_pow_zn(temp2, out.h, DID_elem); // h^(DID_elem)
    element_mul(out.com, temp1, temp2);
    element_clear(temp1);
    element_clear(temp2);



    // Adım 6: KoR İspatının Hesaplanması (Algoritma 5)
    element_t r1, r2, r3;
    element_init_Zr(r1, params.pairing);  element_random(r1);
    element_init_Zr(r2, params.pairing);  element_random(r2);
    element_init_Zr(r3, params.pairing);  element_random(r3);

    element_t com_prime_i;
    element_init_G1(com_prime_i, params.pairing);
    element_pow_zn(temp1, params.g1, r1);  // temp1 = g1^r1
    element_pow_zn(temp2, params.h1, r2);  // temp2 = h1^r2
    element_mul(com_prime_i, temp1, temp2); // com'_i = g1^r1 * h1^r2
    element_clear(temp1);
    element_clear(temp2);


    element_t com_prime;
    element_init_G1(com_prime, params.pairing);
    element_pow_zn(temp1, params.g1, r3);   // temp1 = g1^r3
    element_pow_zn(temp2, out.h, r2);    // temp2 = h^r2
    element_mul(com_prime, temp1, temp2);  // com' = g1^r3 * h^r2
    element_clear(temp1);
    element_clear(temp2);


    // c = Hash(g1, h, h1, com, com', comi, com'_i)
    std::vector<std::string> hashData;
    hashData.push_back(canonicalElementToHex(params.g1));
    hashData.push_back(canonicalElementToHex(out.h));
    hashData.push_back(canonicalElementToHex(params.h1));
    hashData.push_back(canonicalElementToHex(out.com));
    hashData.push_back(canonicalElementToHex(com_prime));
    hashData.push_back(canonicalElementToHex(out.comi));
    hashData.push_back(canonicalElementToHex(com_prime_i));

    element_init_Zr(out.pi_s.c, params.pairing);
    hashVectorToZr(hashData, params, out.pi_s.c);

    // s1 = r1 - c * o_i
    element_init_Zr(out.pi_s.s1, params.pairing);
    element_mul(temp1, out.pi_s.c, o_i);   // temp1 = c * o_i
    element_sub(out.pi_s.s1, r1, temp1);  // s1 = r1 - temp1

    // s2 = r2 - c * DID_elem
    element_init_Zr(out.pi_s.s2, params.pairing);
    element_mul(temp1, out.pi_s.c, DID_elem); // temp1 = c * DID_elem
    element_sub(out.pi_s.s2, r2, temp1);  // s2 = r2 - temp1

    // s3 = r3 - c * o
    element_init_Zr(out.pi_s.s3, params.pairing);
    element_mul(temp1, out.pi_s.c, o);     // temp1 = c * o
    element_sub(out.pi_s.s3, r3, temp1);  // s3 = r3 - temp1

    element_clear(temp1); // Artık temp1'e ihtiyaç yok.

    // Temizlik
    element_clear(r1);
    element_clear(r2);
    element_clear(r3);
    element_clear(com_prime);
    element_clear(com_prime_i);
    element_clear(o_i);
    element_clear(o);
    element_clear(DID_elem);

    return out;
}