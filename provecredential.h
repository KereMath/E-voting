#ifndef PROVECREDENTIAL_H
#define PROVECREDENTIAL_H

#include "setup.h"
#include "keygen.h"   // MasterVerKey tanımlı (mvk.vkm1, mvk.vkm2, mvk.vkm3)
#include "aggregate.h"
#include <string>

/*
  ProveCredentialOutput:  
    - sigmaRnd: Randomized aggregate imza, σ'' = (h'', s'')
    - k: Hesaplanan k değeri: k = α₂ · (β₂)^(DID) · g₂^r
    - proof_v: KoR proof (π_v) – burada k’nin SHA512 hash’i olarak hesaplanmıştır.
*/
struct ProveCredentialOutput {
    AggregateSignature sigmaRnd;
    element_t k;
    std::string proof_v;
};

/*
  proveCredential: Algoritma 15 TIAC İmza Kanıtı.
  Girdi:
    - params: TIAC parametreleri
    - aggSig: Aggregate imza σ = (h, s)
    - mvk: Master verification key (mvk = (vkm1, vkm2, vkm3)) – burada
           vkm1 = α₂, vkm2 = β₂, vkm3 = β₁
    - didStr: Seçmenin DID (hex string)
  Çıktı:
    - ProveCredentialOutput: σ_Rnd = (σ'', k) ve π_v (KoR proof)
  
  Not: Algoritma 16 (KoR) kısmı, burada k’nin SHA512 hash’i ile simüle edilmiştir.
*/
ProveCredentialOutput proveCredential(
    TIACParams &params,
    AggregateSignature &aggSig,
    MasterVerKey &mvk,
    const std::string &didStr
);

#endif
