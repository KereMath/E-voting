#ifndef KEYGEN_H
#define KEYGEN_H

#include "setup.h"
#include <vector>

// MasterVerKey (mvk): Ana doğrulama anahtarı bileşenleri
//   alpha2 = g2^x
//   beta2  = g2^y
//   beta1  = g1^y
struct MasterVerKey {
    element_t alpha2; 
    element_t beta2;  
    element_t beta1;  
};

// EAKey: Bir EA otoritesinin gizli/açık anahtar bileşenleri
//  sgk1 = xm, sgk2 = ym (gizli kısımlar - polinomdan gelen)
//  vkm1 = g2^xm, vkm2 = g2^ym, vkm3 = g1^ym (doğrulama kısımları)
struct EAKey {
    element_t sgk1;
    element_t sgk2;
    element_t vkm1;
    element_t vkm2;
    element_t vkm3;
};

// KeyGenOutput: 
//   mvk   : MasterVerKey
//   eaKeys: Tüm EA otoriteleri için anahtar dizisi
struct KeyGenOutput {
    MasterVerKey mvk;
    std::vector<EAKey> eaKeys;
};

// Algoritma 2: Coconut TTP ile Anahtar Üretimi
//   Girdi : params, t (eşik), ne (EA otorite sayısı)
//   Çıktı : mvk ve sgk, vkm (eaKeys)
KeyGenOutput keygen(TIACParams &params, int t, int ne);

#endif
