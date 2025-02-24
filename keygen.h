#ifndef KEYGEN_H
#define KEYGEN_H

#include <pbc/pbc.h>
#include <vector>
#include <string>
#include "setup.h"

/**
 * Her EA (Yetkili Otorite) için tutulan veriler
 * (polinom sabit terimleri, commitments, local paylar, vb.)
 */
struct EAKey {
    // x0, y0  (EA_i’nin polinom sabit katsayıları)
    element_t x0; 
    element_t y0; 

    // t+1 katsayı için commitment dizileri:
    //   Vx[j] = g2^( x_{ij} )
    //   Vy[j] = g2^( y_{ij} )
    //   Vyprime[j] = g1^( y_{ij} )
    std::vector<element_t> Vx;
    std::vector<element_t> Vy;
    std::vector<element_t> Vyprime;

    // Final: local signing share (sgk1, sgk2)
    element_t sgk1;  // ∑_{l in Q} F_l(i)
    element_t sgk2;  // ∑_{l in Q} G_l(i)

    // Final: local verification share (vki1, vki2, vki3)
    element_t vki1;  // g2^(sgk1)
    element_t vki2;  // g2^(sgk2)
    element_t vki3;  // g1^(sgk2)
};

/**
 * Master verification key (mvk) = (vk1, vk2, vk3)
 * = ( ∏_{i in Q} Vx_i0,  ∏_{i in Q} Vy_i0,  ∏_{i in Q} Vy'_i0 )
 * = ( g2^( sum x_i0 ), g2^( sum y_i0 ), g1^( sum y_i0 ) ).
 */
struct MasterVK {
    element_t vk1; 
    element_t vk2;
    element_t vk3;
};

/**
 * Master signing key (msgk) = (sk1, sk2) = ( sum x_i0, sum y_i0 )
 */
struct MasterSK {
    element_t sk1;
    element_t sk2;
};

/**
 * Bu struct, keygen sonunda dönen tüm değerleri tutar.
 */
struct KeyGenOutput {
    MasterVK mvk;              // Genel doğrulama anahtarı
    MasterSK msgk;             // Master gizli anahtar
    std::vector<EAKey> eaKeys; // Her EA için ayrıntılar
};

/**
 * Coconut TTP’siz Anahtar Üretimi (Pedersen’s DKG).
 * 
 * Girdi:
 *   - params (setup sonucu)
 *   - t (eşik değeri)
 *   - n (EA sayısı)
 * Çıktı:
 *   - KeyGenOutput (mvk, msgk, her EA'nın payları)
 *
 * NOT: Şikayet ve diskalifiye aşamaları basitleştirilmiştir 
 * (kimse hata yapmıyor varsayımı).
 */
KeyGenOutput keygen(TIACParams &params, int t, int n);

#endif // KEYGEN_H
