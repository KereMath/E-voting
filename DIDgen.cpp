#include "DIDgen.h"
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <sstream>
#include <iomanip>
#include <iostream>

DID createDID(const std::string &realID) {
    DID didObj;
    didObj.realID = realID;
    
    // Rastgele x: 256-bit (32 byte) uzunluğunda bir sayı üretelim.
    const int numBytes = 32;
    unsigned char randomBytes[numBytes];
    if (RAND_bytes(randomBytes, numBytes) != 1) {
        std::cerr << "Rastgele sayı üretilirken hata oluştu." << std::endl;
        // Hata durumunu uygun şekilde yönetin.
    }
    
    // Üretilen byte dizisini hex string'e çevirip, x olarak sakla.
    std::stringstream xss;
    for (int i = 0; i < numBytes; i++) {
        xss << std::hex << std::setw(2) << std::setfill('0') << (int)randomBytes[i];
    }
    didObj.x = xss.str();
    
    // x değeri ile gerçek ID'yi birleştir.
    std::string concat = didObj.x + realID;
    
    // SHA‑512 hash hesapla.
    unsigned char hash[SHA512_DIGEST_LENGTH];
    SHA512(reinterpret_cast<const unsigned char*>(concat.c_str()), concat.size(), hash);
    
    // Hash sonucunu hex string’e dönüştür.
    std::stringstream hashSS;
    for (int i = 0; i < SHA512_DIGEST_LENGTH; i++) {
        hashSS << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
    }
    didObj.did = hashSS.str();
    
    return didObj;
}
