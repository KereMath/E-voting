#ifndef VERIFY_CREDENTIAL_H
#define VERIFY_CREDENTIAL_H

#include "provecredential.h"  // ProveCredentialOutput tanımı için
#include "setup.h"            // TIACParams tanımı için
#include <string>

// verifyCredential: ProveCredential çıktısındaki KoR tuple ve pairing kontrolü ile imza doğrulamasını yapar.
// Eğer her iki kontrol de başarılı ise true, aksi halde false döndürür.
bool verifyCredential(TIACParams &params, ProveCredentialOutput &pOut);

#endif
