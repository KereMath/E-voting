#ifndef KEYGEN_H
#define KEYGEN_H

#include <pbc/pbc.h>
#include <vector>
#include "setup.h"

/**
 * Coconut TTP’siz Anahtar Üretimi (Pedersen’s DKG) sonrasında elde edilecek
 * payları ve genel anahtarı tutacak veri yapıları.
 */

// -- 3.1. Her bir EA (Yetkili Otorite) için saklanacak yapı:
struct EAKey {
    // Polinomların sabit terimleri (x_i0, y_i0) -> Algoritma metninde "x_m, y_m" gibi de anılabilir
    element_t x_m; // f0 (F_i(0)) -> EA_i için
    element_t y_m; // g0 (G_i(0)) -> EA_i için

    // EA_i'nın local imza payları (signing key share)
    // sgk1 = ∑_{l∈Q} F_l(i), sgk2 = ∑_{l∈Q} G_l(i)
    element_t sgk1;
    element_t sgk2;

    // EA_i'nın doğrulama anahtarı payları (public verification share)
    // vki = (vki1, vki2, vki3)
    element_t vki1; // g2^(sgk1)
    element_t vki2; // g2^(sgk2)
    element_t vki3; // g1^(sgk2)
};

// -- 3.2. Master doğrulama anahtarı (mvk)
// mvk = (vk1, vk2, vk3) = ( ∏ g2^{x_i0}, ∏ g2^{y_i0}, ∏ g1^{y_i0} ) = (g2^x, g2^y, g1^y) 
struct MasterVK {
    element_t vk1; // g2^( Σ x_i0 )
    element_t vk2; // g2^( Σ y_i0 )
    element_t vk3; // g1^( Σ y_i0 )
};

// -- 3.3. Master signing key (msgk) - opsiyonel (kullanacaksak)
struct MasterSK {
    element_t sk1; // Σ x_i0
    element_t sk2; // Σ y_i0
};

// -- 3.4. KeyGen fonksiyonunun döndürdüğü tüm çıktı:
struct KeyGenOutput {
    MasterVK mvk;              // Genel doğrulama anahtarı
    MasterSK msk;              // Genel imza anahtarı (tam ortak gizli)
    std::vector<EAKey> eaKeys; // Tüm EA otoritelerinin payları
};

/**
 * Coconut TTP’siz Anahtar Üretimi (Pedersen’s DKG).
 *
 * Girdi:
 *   - params: Setup'ta elde edilen (G1, G2, p, pairing, vs.)
 *   - t: Eşik değeri
 *   - n: EA (seçim otoritesi) sayısı
 *
 * Çıktı:
 *   - KeyGenOutput: Master public key (mvk), master secret key (msk)
 *     ve her EA için local paylar (EAKey).
 *
 * Bu örnekte şikayet/diskalifiye mekanizması basit tutulmuş, herkes
 * geçerli pay üretiyor varsayılmıştır.
 */
KeyGenOutput keygen(TIACParams &params, int t, int n);

#endif // KEYGEN_H
