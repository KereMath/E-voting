#ifndef DIDGEN_H
#define DIDGEN_H

#include "setup.h"
#include <vector>
#include <string>

// Her bir seçmen için DID yapısı:
// - realID: Kullanıcının gerçek (örneğin TC kimlik numarası gibi) ID'si (string olarak)
// - x: Rastgele üretilen skaler gizli değer (Zr elemanı)
// - did: Dijital kimlik = g1^(1/(x + ID))
struct DID {
    std::string realID;
    element_t x;   // Rastgele üretilen skaler
    element_t did; // Dijital kimlik
};

// Tüm seçmenlerin DID'lerini tutan yapı
struct DIDGenOutput {
    std::vector<DID> dids;
};

// Belirtilen gerçek ID (numeric string) ve setup parametrelerini kullanarak
// bir seçmen için dijital kimlik (DID) üretir.
// DID = g1^(1/(x + ID))
// x, Zr’de rastgele seçilir.
DID createDID(TIACParams &params, const std::string &realID);

#endif
