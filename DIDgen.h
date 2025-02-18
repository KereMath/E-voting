#ifndef DIDGEN_H
#define DIDGEN_H

#include "setup.h"
#include <string>

// Her seçmen için DID yapısı:
// - realID: Gerçek kimlik numarası (11 haneli sayısal string)
// - x: Seçmenin rastgele ürettiği skaler (Zr elemanı)
// - did: Dijital kimlik (SHA-512 hash sonucu, hex formatında)
struct DID {
    std::string realID;
    element_t x;      
    std::string did;  
};

// Belirtilen gerçek ID ve setup parametrelerini kullanarak bir seçmen için DID üretir.
DID createDID(TIACParams &params, const std::string &realID);

#endif
