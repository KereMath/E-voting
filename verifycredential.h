#ifndef VERIFY_CREDENTIAL_H
#define VERIFY_CREDENTIAL_H

#include "setup.h"
#include "provecredential.h"
#include "aggregate.h"
#include <string>

// verifyCredential:
//   Girdiler:
//     - params: TIAC parametreleri
//     - pOut: ProveCredentialOutput, yani ProveCredential aşamasında oluşturulan tuple (σRnd, k, π_v)
//     - mvk: Master Verification Key (α₂, β₂, β₁)
//     - aggSig: AggregateSignature (tüm partial imzaların çarpımından elde edilen imza; burada "com" olarak aggSig.s kullanılacaktır)
//   İşlem:
//     Algoritma 17'ye göre KoR kontrolü yapılır, ardından Algoritma 18’e göre pairing kontrolü yapılır.
//   Çıktı:
//     Eğer her iki kontrol de geçiyorsa true, aksi halde false.
bool verifyCredential(TIACParams &params,
                      ProveCredentialOutput &pOut,
                      MasterVerKey &mvk,
                      AggregateSignature &aggSig);

#endif
