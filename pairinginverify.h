#ifndef PAIRINGINVERIFY_H
#define PAIRINGINVERIFY_H

#include "setup.h"
#include "provecredential.h"

// Pairing Check fonksiyonu: 
// Verilen ProveCredentialOutput içindeki sigmaRnd (yani h'' ve s'') ile k değeri kullanılarak
// pairing hesaplaması yapılır: e(h'', k) ?= e(s'', g2).
// Eğer eşleşiyorsa pairing correct yazdırır ve true döner, aksi halde pairing failed yazdırır ve false döner.
bool pairingCheck(TIACParams &params, ProveCredentialOutput &pOut);

#endif
