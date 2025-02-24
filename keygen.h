#ifndef KEYGEN_H
#define KEYGEN_H

#include <pbc/pbc.h>
#include <vector>
#include "setup.h"

/**
 *  Her EA (Yetkili Otorite) için üretilecek paylar ve
 *  anahtar bileşenlerini saklayan struct.
 */
struct EAKey {
    // Polinomların sabit terimleri (x_i0, y_i0)
    element_t x_m; // F_i(0)
    element_t y_m; // G_i(0)

    // İmza payları (sgk1, sgk2) = ( ∑ F_l(i),  ∑ G_l(i) )
    element_t sgk1;
    element_t sgk2;

    // Doğrulama payları (vki1, vki2, vki3)
    // vki1 = g2^(sgk1), vki2 = g2^(sgk2), vki3 = g1^(sgk2)
    element_t vki1;
    element_t vki2;
    element_t vki3;
};

/**
 *  Master Doğrulama Anahtarı (mvk) = (vk1, vk2, vk3)
 *  = (g2^(Σ x_i0),  g2^(Σ y_i0),  g1^(Σ y_i0))
 */
struct MasterVK {
    element_t vk1;
    element_t vk2;
    element_t vk3;
};

/**
 *  Master Gizli Anahtar (msk) = (sk1, sk2)
 *  = (Σ x_i0,  Σ y_i0)
 */
struct MasterSK {
    element_t sk1;
    element_t sk2;
};

/**
 *  KeyGen sonrası dönen tüm veriyi tutan yapı.
 */
struct KeyGenOutput {
    MasterVK mvk;             // Genel doğrulama anahtarı
    MasterSK msk;             // Ortak gizli anahtar (opsiyonel kullanım)
    std::vector<EAKey> eaKeys; // Her EA için paylar
};

/**
 *  Coconut TTP’siz Anahtar Üretimi (Pedersen’s DKG) (şikayet yok)
 *  Girdi: params (setup), t (eşik), n (EA sayısı)
 *  Çıktı: Master public key (mvk), master secret key (msk),
 *         ve EAKey payları.
 */
KeyGenOutput keygen(TIACParams &params, int t, int n);

#endif // KEYGEN_H
