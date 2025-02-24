#ifndef KEYGEN_H
#define KEYGEN_H

#include "setup.h"
#include <vector>

// MasterVerKey (mvk): Ana doğrulama anahtarını (α2, β2, β1) tutar
//  - alpha2 = g2^x
//  - beta2  = g2^y
//  - beta1  = g1^y
struct MasterVerKey {
    element_t alpha2; 
    element_t beta2;  
    element_t beta1;  
};

// Her bir EA otoritesi için oluşturulan alt anahtarlar (sgkm, vkm):
//  - sgk1, sgk2 -> (xm, ym) polinom değerleri (gizli imza anahtarları)
//  - vkm1 = g2^(xm), vkm2 = g2^(ym), vkm3 = g1^(ym)
struct EAKey {
    element_t sgk1;   
    element_t sgk2;   
    element_t vkm1;   
    element_t vkm2;   
    element_t vkm3;   
};

// KeyGenOutput: KeyGen (Anahtar üretimi) çıktısı
//  - mvk : MasterVerKey
//  - eaKeys : Bütün EA otoriteleri için EAKey dizisi
struct KeyGenOutput {
    MasterVerKey mvk;
    std::vector<EAKey> eaKeys;
};

// Algoritma 2: Coconut TTP ile Anahtar Üretimi
//  Girdi: params, t (eşik), ne (EA sayısı)
//  Çıktı: MasterVerKey (mvk) ve her EA otoritesinin sgk, vkm değerleri
KeyGenOutput keygen(const TIACParams &params, int t, int ne);

#endif
