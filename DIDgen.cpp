#include "DIDgen.h"
#include <pbc/pbc.h>
#include <gmp.h>
#include <openssl/sha.h>
#include <sstream>
#include <iomanip>
#include <iostream>

DID createDID(TIACParams &params, const std::string &realID) {
    DID didObj;
    didObj.realID = realID;
    
    // x: Zr’de rastgele skaler değer üret
    element_init_Zr(didObj.x, params.pairing);
    element_random(didObj.x);
    
    // x değerini string olarak al (base 10)
    char x_buffer[256];
    element_snprintf(x_buffer, sizeof(x_buffer), "%B", didObj.x);
    std::string xStr(x_buffer);
    
    // xStr ve realID'yi birleştir
    std::string concat = xStr + realID;  // araya ayraç eklemek isteğe bağlıdır
    
    // SHA-512 hash hesapla
    unsigned char hash[SHA512_DIGEST_LENGTH];
    SHA512(reinterpret_cast<const unsigned char*>(concat.c_str()), concat.size(), hash);
    
    // Hash sonucunu hex string’e dönüştür
    std::stringstream ss;
    for (int i = 0; i < SHA512_DIGEST_LENGTH; i++) {
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
    }
    didObj.did = ss.str();
    
    return didObj;
}
