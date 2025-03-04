#ifndef UNBLINDSIGN_H
#define UNBLINDSIGN_H

#include "setup.h"
#include "prepareblindsign.h"
#include "keygen.h"
#include "blindsign.h"
#include <string>

// Global: G1 elemanını hex string'e çevirir.
std::string elementToStringG1(element_t elem);

/*
  UnblindSignature: Alg. 13 TIAC Körleştirme Faktörünün Çıkarılması sonucunda elde edilen
  unblind imza: σₘ = (h, sₘ)
  Debug alanında ara hesaplama sonuçlarının string gösterimleri saklanır.
*/
struct UnblindSignature {
    element_t h;   // Blind imzadan alınan h (aynı h)
    element_t s_m; // Unblind imza bileşeni sₘ
    struct {
        std::string hash_comi;    // Hash(comi) sonucu
        std::string computed_s_m; // Hesaplanan sₘ = cm·(β₂)^(–o)
        std::string pairing_lhs;  // e(h, α₂·(β₂)^(DID)) (string gösterimi)
        std::string pairing_rhs;  // e(sₘ, g2) (string gösterimi)
    } debug;
};

/*
  unblindSign: Alg. 13 – TIAC Körleştirme Faktörünün Çıkarılması
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
