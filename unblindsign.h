#ifndef UNBLINDSIGN_H
#define UNBLINDSIGN_H

#include "setup.h"
#include "prepareblindsign.h"
#include "keygen.h"
#include "blindsign.h"
#include <string>

// Global olarak kullanılacak: G1 elemanını hex string'e çevirir.
std::string elementToStringG1(element_t elem);

/*
  UnblindSignature: Algoritma 13 TIAC Körleştirme Faktörünün Çıkarılması sonucunda
  elde edilen unblind imza: σₘ = (h, sₘ)
  Debug alanında ara hesaplama sonuçlarının string gösterimleri saklanır.
*/
struct UnblindSignature {
    element_t h;   // G1, aynı h
    element_t s_m; // G1, unblind imza bileşeni
    struct {
        std::string hash_comi;    // Hash(comi) sonucu
        std::string computed_s_m; // Hesaplanan sₘ = cm·(β₂)^(–o)
        std::string pairing_lhs;  // e(h, α₂·(β₂)^(didInt)) değeri (string gösterimi)
        std::string pairing_rhs;  // e(sₘ, g2) değeri (string gösterimi)
    } debug;
};

/*
  unblindSign: Algoritma 13 – TIAC Körleştirme Faktörünün Çıkarılması
  Girdi:
    - params: TIAC parametreleri
    - bsOut: PrepareBlindSignOutput (comi, h, com, o, vs.)
    - blindSig: BlindSignature (σ′ₘ = (h, cm))
    - eaKey: EA Authority'nin public key bileşenleri (EAKey; vkm1, vkm2, vkm3)
    - didStr: Votera ait DID (hex string)
  Çıktı:
    - UnblindSignature: σₘ = (h, sₘ) ve debug bilgileri
*/
UnblindSignature unblindSign(
    TIACParams &params,
    PrepareBlindSignOutput &bsOut,
    BlindSignature &blindSig,
    EAKey &eaKey,
    const std::string &didStr
);

#endif
