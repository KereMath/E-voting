#ifndef DIDGEN_H
#define DIDGEN_H

#include "setup.h"
#include <string>

// Her seçmen için DID yapısı:
// - realID: Sabit 11 haneli gerçek kimlik (örneğin TC kimlik numarası)
// - x: Rastgele seçilen skaler değer (Zr elemanı)
// - did: SHA-512 hash sonucu (hex formatında) = hash512( x || realID )
struct DID {
    std::string realID;
    element_t x;      // Rastgele skaler (Zr)
    std::string did;  // Hash512 sonucu (hex string)
};

// Belirtilen gerçek ID (string) ve setup parametrelerini kullanarak
// bir seçmen için dijital kimlik (DID) üretir.
DID createDID(TIACParams &params, const std::string &realID);

#endif
