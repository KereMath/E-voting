#ifndef KEYGEN_H
#define KEYGEN_H

#include <vector>
#include "setup.h"

// EA (Yetkili Otorite) için anahtar çiftleri:
// sgk: EA'nın imza anahtar payı
// vkm: EA'nın doğrulama anahtar bileşenleri
struct EAKey {
    element_t sgk1; // ∏_{l∈Q} F_l(i)
    element_t sgk2; // ∏_{l∈Q} G_l(i)
    element_t vkm1; // vkm1 = g2^(sgk1)
    element_t vkm2; // vkm2 = g2^(sgk2)
    element_t vkm3; // vkm3 = g1^(sgk2)
};

// Master doğrulama anahtarı (mvk)
// mvk = (alpha2, beta2, beta1) = ( g1^(∏_{i∈Q} F_i(0)^2),
//                                   g1^(∏_{i∈Q} G_i(0)^2),
//                                   g1^(∏_{i∈Q} G_i(0)) )
struct MasterVK {
    element_t alpha2;
    element_t beta2;
    element_t beta1;
};

// Key Generation işleminin çıktı yapısı
struct KeyGenOutput {
    MasterVK mvk;
    std::vector<EAKey> eaKeys; // EA otoritelerinin anahtar çiftleri (i = 1,..., ne)
};

// Coconut TTP’siz Anahtar Üretimi (Pedersen’s DKG) fonksiyonu
// Girdi: params, t (eşik; polinom derecesi = t-1), ne (EA sayısı)
// Çıktı: mvk ve her EA için (sgk, vkm)
KeyGenOutput keygen(TIACParams &params, int t, int ne);

#endif
