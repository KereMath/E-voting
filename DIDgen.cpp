#include "DIDgen.h"
#include <pbc/pbc.h>
#include <gmp.h>
#include <iostream>

DID createDID(TIACParams &params, const std::string &realID) {
    DID didObj;
    didObj.realID = realID;
    
    // x: Zr'de rastgele skaler değer
    element_init_Zr(didObj.x, params.pairing);
    element_random(didObj.x);
    
    // Gerçek ID (string) sayısal olduğundan mpz_t kullanarak Zr elemanı oluşturuyoruz.
    mpz_t id_mpz;
    mpz_init(id_mpz);
    // Gerçek ID'yi ondalık (base 10) sayı olarak ayarla.
    if(mpz_set_str(id_mpz, realID.c_str(), 10) != 0) {
        std::cerr << "Error: Gerçek ID degeri sayısal degil!" << std::endl;
    }
    
    element_t idElem;
    element_init_Zr(idElem, params.pairing);
    element_set_mpz(idElem, id_mpz);
    
    // Toplam: x + idElem
    element_t sum;
    element_init_Zr(sum, params.pairing);
    element_add(sum, didObj.x, idElem);
    
    // İnvers: 1/(x + idElem)
    element_t inv;
    element_init_Zr(inv, params.pairing);
    if (element_invert(inv, sum) == 0) {
        std::cerr << "Error: Inversion failed (x + ID is zero)!" << std::endl;
    }
    
    // DID = g1^(inv)
    element_init_G1(didObj.did, params.pairing);
    element_pow_zn(didObj.did, params.g1, inv);
    
    // Temizlik
    element_clear(idElem);
    element_clear(sum);
    element_clear(inv);
    mpz_clear(id_mpz);
    
    return didObj;
}
