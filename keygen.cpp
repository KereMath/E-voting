#include "keygen.h"
#include <iostream>
#include <cassert>

/**
 * Yardımcı: polinom değerlendirme
 * F[i][j] => F_i(X) polinomunun j. katsayısı
 * Katsayılar "element_s" (C struct) olarak saklanıyor;
 *   evaluatePoly(F[i], t, X, outVal)
 */
static void evaluatePoly(element_s *coeffs, // katsayı dizisi (t+1 uzunluk)
                         int t,            // derecenin en büyük indexi
                         int X,
                         TIACParams &params,
                         element_t outVal)
{
    // outVal = ∑_{k=0..t} coeffs[k] * X^k
    element_set0(outVal);

    element_t xVal;
    element_init_Zr(xVal, params.pairing);
    element_set_si(xVal, X);

    element_t power;
    element_init_Zr(power, params.pairing);
    element_set1(power);

    element_t tmp;
    element_init_Zr(tmp, params.pairing);

    for (int k = 0; k <= t; k++) {
        // tmp = coeffs[k] * power
        element_mul(tmp, &coeffs[k], power);
        // outVal += tmp
        element_add(outVal, outVal, tmp);

        // power *= xVal
        element_mul(power, power, xVal);
    }

    element_clear(xVal);
    element_clear(power);
    element_clear(tmp);
}

/**
 * Pedersen’s DKG: n EA, eşik t.
 * 
 *  - F_i(X), G_i(X) polinomları (derece t)
 *  - Commitments: Vx, Vy, Vy'
 *  - Pay dağıtımı & doğrulama (şikayet yok)
 *  - Master key (mvk, msgk) & local paylar (sgk, vki)
 */
KeyGenOutput keygen(TIACParams &params, int t, int n) {
    KeyGenOutput out;
    // out.eaKeys => EAKey*, her EA'nın kaydı
    out.eaKeys = new EAKey[n];  // Bellek ayır

    // 1) Polinom katsayıları: F[i], G[i]
    //    i=0..n-1 => her i. EA
    //    F[i] = new element_s[t+1]
    //    G[i] = new element_s[t+1]
    element_s **F = new element_s*[n];
    element_s **G = new element_s*[n];

    for(int i=0; i<n; i++){
        F[i] = new element_s[t+1];
        G[i] = new element_s[t+1];

        // init + random
        for(int j=0; j<=t; j++){
            // F[i][j]
            element_init_Zr(&F[i][j], params.pairing);
            element_random(&F[i][j]);
            // G[i][j]
            element_init_Zr(&G[i][j], params.pairing);
            element_random(&G[i][j]);
        }
    }

    // 2) Commitments: Vx, Vy, Vy' (t+1 uzunluk)
    //    EAKey'lerde pointer dizisi ayıracağız
    for(int i=0; i<n; i++){
        out.eaKeys[i].Vx = new element_t[t+1];
        out.eaKeys[i].Vy = new element_t[t+1];
        out.eaKeys[i].Vyprime = new element_t[t+1];

        // t+1 init
        for(int j=0; j<=t; j++){
            element_init_G2(out.eaKeys[i].Vx[j], params.pairing);
            element_init_G2(out.eaKeys[i].Vy[j], params.pairing);
            element_init_G1(out.eaKeys[i].Vyprime[j], params.pairing);

            // Vx_{i,j} = g2^( F[i][j] )
            element_pow_zn(out.eaKeys[i].Vx[j], params.g2, &F[i][j]);
            // Vy_{i,j} = g2^( G[i][j] )
            element_pow_zn(out.eaKeys[i].Vy[j], params.g2, &G[i][j]);
            // Vy'_{i,j} = g1^( G[i][j] )
            element_pow_zn(out.eaKeys[i].Vyprime[j], params.g1, &G[i][j]);
        }
    }

    // 3) sabit terimler x0, y0 => EAKey.x0, y0
    for(int i=0; i<n; i++){
        element_init_Zr(out.eaKeys[i].x0, params.pairing);
        element_set(out.eaKeys[i].x0, &F[i][0]);

        element_init_Zr(out.eaKeys[i].y0, params.pairing);
        element_set(out.eaKeys[i].y0, &G[i][0]);
    }

    // 4) Pay doğrulama (şikayetsiz)
    {
        element_t fVal, gVal;
        element_init_Zr(fVal, params.pairing);
        element_init_Zr(gVal, params.pairing);

        element_t lhsG2, rhsG2;
        element_init_G2(lhsG2, params.pairing);
        element_init_G2(rhsG2, params.pairing);

        element_t lhsG1, rhsG1;
        element_init_G1(lhsG1, params.pairing);
        element_init_G1(rhsG1, params.pairing);

        element_t powL;
        element_init_Zr(powL, params.pairing);

        for(int i=0; i<n; i++){
            for(int L=1; L<=n; L++){
                // F_i(L), G_i(L)
                evaluatePoly(F[i], t, L, params, fVal);
                evaluatePoly(G[i], t, L, params, gVal);

                // Check F_i(L):
                //  g2^F_i(L) ?= ∏ Vx[i][j]^(L^j)
                element_pow_zn(lhsG2, params.g2, fVal);

                element_set1(rhsG2);
                element_set1(powL);
                for(int j=0; j<=t; j++){
                    if(j>0) element_mul_si(powL, powL, L);
                    element_t tmpG2;
                    element_init_G2(tmpG2, params.pairing);
                    element_pow_zn(tmpG2, out.eaKeys[i].Vx[j], powL);
                    element_mul(rhsG2, rhsG2, tmpG2);
                    element_clear(tmpG2);
                }
                if(element_cmp(lhsG2, rhsG2) != 0){
                    std::cerr << "[WARN] F_i("<<L<<") mismatch => i=" << i << "\n";
                }

                // Check G_i(L) in G2:
                element_pow_zn(lhsG2, params.g2, gVal);
                element_set1(rhsG2);
                element_set1(powL);
                for(int j=0; j<=t; j++){
                    if(j>0) element_mul_si(powL, powL, L);
                    element_t tmpG2;
                    element_init_G2(tmpG2, params.pairing);
                    element_pow_zn(tmpG2, out.eaKeys[i].Vy[j], powL);
                    element_mul(rhsG2, rhsG2, tmpG2);
                    element_clear(tmpG2);
                }
                if(element_cmp(lhsG2, rhsG2) != 0){
                    std::cerr << "[WARN] G_i("<<L<<") mismatch G2 => i=" << i << "\n";
                }

                // Check G_i(L) in G1:
                element_pow_zn(lhsG1, params.g1, gVal);
                element_set1(rhsG1);
                element_set1(powL);
                for(int j=0; j<=t; j++){
                    if(j>0) element_mul_si(powL, powL, L);
                    element_t tmpG1;
                    element_init_G1(tmpG1, params.pairing);
                    element_pow_zn(tmpG1, out.eaKeys[i].Vyprime[j], powL);
                    element_mul(rhsG1, rhsG1, tmpG1);
                    element_clear(tmpG1);
                }
                if(element_cmp(lhsG1, rhsG1) != 0){
                    std::cerr << "[WARN] G_i("<<L<<") mismatch G1 => i=" << i << "\n";
                }
            }
        }

        element_clear(fVal);
        element_clear(gVal);
        element_clear(lhsG2);
        element_clear(rhsG2);
        element_clear(lhsG1);
        element_clear(rhsG1);
        element_clear(powL);
    }

    // 5) Master Verification Key (mvk) = ( ∏ Vx[i][0], ∏ Vy[i][0], ∏ Vy'[i][0] )
    element_init_G2(out.mvk.vk1, params.pairing);
    element_init_G2(out.mvk.vk2, params.pairing);
    element_init_G1(out.mvk.vk3, params.pairing);

    element_set1(out.mvk.vk1);
    element_set1(out.mvk.vk2);
    element_set1(out.mvk.vk3);

    for(int i=0; i<n; i++){
        element_mul(out.mvk.vk1, out.mvk.vk1, out.eaKeys[i].Vx[0]);
        element_mul(out.mvk.vk2, out.mvk.vk2, out.eaKeys[i].Vy[0]);
        element_mul(out.mvk.vk3, out.mvk.vk3, out.eaKeys[i].Vyprime[0]);
    }

    // 6) Master Signing Key (msgk) = ( ∑ F[i][0], ∑ G[i][0] )
    element_init_Zr(out.msgk.sk1, params.pairing);
    element_init_Zr(out.msgk.sk2, params.pairing);
    element_set0(out.msgk.sk1);
    element_set0(out.msgk.sk2);

    for(int i=0; i<n; i++){
        element_add(out.msgk.sk1, out.msgk.sk1, &F[i][0]);
        element_add(out.msgk.sk2, out.msgk.sk2, &G[i][0]);
    }

    // 7) Local pay: sgk1 = ∑ F_l(i+1), sgk2 = ∑ G_l(i+1)
    //    vki => (g2^sgk1, g2^sgk2, g1^sgk2)
    for(int i=0; i<n; i++){
        element_init_Zr(out.eaKeys[i].sgk1, params.pairing);
        element_init_Zr(out.eaKeys[i].sgk2, params.pairing);
        element_set0(out.eaKeys[i].sgk1);
        element_set0(out.eaKeys[i].sgk2);

        for(int l=0; l<n; l++){
            element_t valF, valG;
            element_init_Zr(valF, params.pairing);
            element_init_Zr(valG, params.pairing);

            evaluatePoly(F[l], t, i+1, params, valF);
            evaluatePoly(G[l], t, i+1, params, valG);

            element_add(out.eaKeys[i].sgk1, out.eaKeys[i].sgk1, valF);
            element_add(out.eaKeys[i].sgk2, out.eaKeys[i].sgk2, valG);

            element_clear(valF);
            element_clear(valG);
        }

        element_init_G2(out.eaKeys[i].vki1, params.pairing);
        element_init_G2(out.eaKeys[i].vki2, params.pairing);
        element_init_G1(out.eaKeys[i].vki3, params.pairing);

        element_pow_zn(out.eaKeys[i].vki1, params.g2, out.eaKeys[i].sgk1);
        element_pow_zn(out.eaKeys[i].vki2, params.g2, out.eaKeys[i].sgk2);
        element_pow_zn(out.eaKeys[i].vki3, params.g1, out.eaKeys[i].sgk2);
    }

    // 8) Polinom belleğini temizle
    //    element_clear vs. new'da ayırdığımız alan => delete
    for(int i=0; i<n; i++){
        for(int j=0; j<=t; j++){
            element_clear(&F[i][j]);
            element_clear(&G[i][j]);
        }
        delete[] F[i];
        delete[] G[i];
    }
    delete[] F;
    delete[] G;

    return out;
}
