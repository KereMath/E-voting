#ifndef CHECKKORVERIFY_H
#define CHECKKORVERIFY_H

#include "setup.h"
#include "keygen.h"          // MasterVerificationKey (mvk) için
#include "kor.h"             // KoR proof içerisindeki c, s1, s2, s3 için
#include "provecredential.h" // ProveCredentialOutput içinde (k, c, s1, s2, s3) var
#include <string>

/**
 * Knowledge of Representation Proof Verification (Alg.17)
 * @param params      : Sistem parametreleri (g1, g2, pairing, vb.)
 * @param proveRes    : ProveCredential aşamasında üretilen sonuç (k, c, s1, s2, s3 vs.)
 * @param mvk         : MasterVerificationKey (alpha2, beta2)
 * @param com_str     : Orijinal commitment string (preparedOutputs[i].debug.com)
 * @param h_agg       : Aggregate aşamasında üretilen h (aggregateResults[i].h)
 * @return            : Doğrulama başarılıysa true, aksi halde false
 *
 * Alg.17 Adımları:
 *   1) k'' = g2^s1 * alpha2^(1−c) * k^c * beta2^s2
 *   2) com'' = g1^s3 * h^s2 * com^c
 *   3) c' = Hash(g1, g2, h, com, com'', k, k'')
 *   4) eğer c' != c ise return false
 *      aksi takdirde return true
 */
bool checkKoRVerify(
    TIACParams &params,
    const ProveCredentialOutput &proveRes,
    const MasterVerificationKey &mvk,
    const std::string &com_str,
    const element_t h_agg
);

#endif // CHECKKORVERIFY_H
