#ifndef DIDGEN_H
#define DIDGEN_H

#include "setup.h"
#include <string>

// DID yapısı:
//  - x   : Her kullanıcının rastgele seçilen gizli değeri (mpz_t olarak saklanır)
//  - did : ID + x_string birleştirmesinin SHA-512 özeti (hex string)
struct DID {
    mpz_t x;
    std::string did;
};

// createDID:
//  Parametreler:
//   - params: Sistemin TIACParams (pairing, p vs. içerebilir)
//   - userID: Örneğin "44283765012" gibi 11 haneli string
//  İşlem:
//   - Rastgele x üret (örneğin [0, p-1] modunda)
//   - x'i stringe çevirerek userID ile birleştir (concatenate)
//   - SHA-512 ile hash'le, hex string olarak elde et
//   - DID struct'ını döndür
DID createDID(const TIACParams &params, const std::string &userID);

#endif
