#ifndef CHECKKORVERIFY_H
#define CHECKKORVERIFY_H

#include "setup.h"
#include "keygen.h"          // MasterVerKey (mvk) buradan geliyor
#include "kor.h"             // KoR proof içerisindeki c, s1, s2, s3
#include "provecredential.h" // ProveCredentialOutput -> (k, c, s1, s2, s3)
#include <string>

/**
 * Knowledge of Representation Proof Verification (Alg.17)
 *
 * @param params   : Sistem parametreleri (g1, g2, pairing, vb.)
 * @param proveRes : ProveCredential aşamasında üretilen sonuç (k, c, s1, s2, s3)
 * @param mvk      : MasterVerKey (alpha2, beta2, beta1)
 * @param com_str  : Orijinal commitment string (preparedOutputs[i].debug.com)
 * @param h_agg    : Aggregate aşamasında üretilen h (aggregateResults[i].h)
 *
 * @return         : Doğrulama başarılıysa true, aksi halde false.
 */
bool checkKoRVerify(
    TIACParams &params,
    const ProveCredentialOutput &proveRes,
    const MasterVerKey &mvk,   // <-- Burada MasterVerKey yerine MasterVerKey struct'ını 'MasterVerKey' olarak düzeltin
    const std::string &com_str,
    const element_t h_agg
);

#endif // CHECKKORVERIFY_H
