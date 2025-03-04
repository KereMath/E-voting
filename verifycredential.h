#ifndef VERIFY_CREDENTIAL_H
#define VERIFY_CREDENTIAL_H

#include "setup.h"
#include "provecredential.h"
#include <string>

/**
 * @brief Verilen ProveCredentialOutput çıktısına göre credential doğrulamasını yapar.
 * 
 * @param params TIAC parametreleri
 * @param pOut ProveCredentialOutput (σRnd, k, proof_v, debug_info)
 * @return true Doğrulama başarılı ise, false başarısız ise.
 */
bool verifyCredential(TIACParams &params, ProveCredentialOutput &pOut);

#endif // VERIFY_CREDENTIAL_H
