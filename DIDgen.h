#ifndef DIDGEN_H
#define DIDGEN_H

#include <string>

// Her seçmen için DID yapısı:
// - realID: Gerçek kimlik numarası (örneğin, 11 haneli sayısal string)
// - x: Rastgele üretilen skaler sayı (hex formatında)
// - did: Dijital kimlik (x ile realID’nin birleştirilip SHA‑512 hash’i, hex formatında)
struct DID {
    std::string realID;
    std::string x;      
    std::string did;  
};

// Belirtilen gerçek ID'yi kullanarak bir seçmen için DID üretir.
DID createDID(const std::string &realID);

#endif
