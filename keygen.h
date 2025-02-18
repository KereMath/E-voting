#ifndef KEYGEN_H
#define KEYGEN_H

#include <vector>
#include "setup.h"

// EA (Yetkili Otorite) için anahtar çifti yapısı
struct EAKey {
    element_t sgk_x; // EA'nın gizli anahtar parçası: v(m)
    element_t sgk_y; // EA'nın gizli anahtar parçası: w(m)
    element_t alpha2; // EA'nın doğrulama anahtar bileşeni: g1^(v(m)^2)
    element_t beta2;  // EA'nın doğrulama anahtar bileşeni: g1^(w(m)^2)
    element_t beta1;  // EA'nın doğrulama anahtar bileşeni: g1^(w(m))
};

// Master doğrulama anahtarı yapısı
struct MasterVK {
    element_t alpha2; // g1^(v(0)^2)
    element_t beta2;  // g1^(w(0)^2)
    element_t beta1;  // g1^(w(0))
};

// Key Generation işleminin çıktı yapısı
struct KeyGenOutput {
    MasterVK mvk;
    std::vector<EAKey> eaKeys; // EA otoritelerinin anahtarları (m ∈ {1, …, ne})
};

// Coconut TTP ile Anahtar Üretimi fonksiyonu
// Girdi: params (setup parametreleri), t (eşik), ne (EA otoritesi sayısı)
// Çıktı: mvk, ve her EA için (sgkm, vkm)
KeyGenOutput keygen(TIACParams &params, int t, int ne);

#endif
