#include "keygen.h"
#include <iostream>
#include <cassert>

/**
 * Yardımcı: polinom değerlendirme (mod r).
 * Katsayılar element_s dizisi (t+1 uzunluk).
 * outVal = F_i(L) = ∑_{k=0..t} coeffs[k] * L^k (mod r).
 */
static void evaluatePoly(element_s *coeffs, // [t+1]
                         int t,            // polinom derecesi
                         int L,
                         TIACParams &params,
                         element_t outVal)
{
    // Başlangıçta 0
    element_set0(outVal);

    // L^k hesaplanacak => L (int) => L mod r'yi * L mod r ... ama standard DKG.
    // Zr alanında polinom = x_{k} * (L^k mod r)
    // Aşağıdaki "element_mul_si(...)" => (mod r).
    element_t xVal;
    element_init_Zr(xVal, params.pairing);
    element_set_si(xVal, L);

    element_t power;
    element_init_Zr(power, params.pairing);
    element_set1(power);

    element_t tmp;
    element_init_Zr(tmp, params.pairing);

    for (int k_i = 0; k_i <= t; k_i++) {
        // tmp = coeffs[k_i] * power
        element_mul(tmp, &coeffs[k_i], power);
        element_add(outVal, outVal, tmp);
        // power *= xVal
        element_mul(power, power, xVal);
    }

    element_clear(xVal);
    element_clear(power);
    element_clear(tmp);
}

/**
 * Pedersen’s DKG (şikayetsiz): 
 * n EA, polinom derecesi t, 
 * F_i(X), G_i(X) mod r, 
 * Commitment check: e.g. g2^F_i(l) = ∏ Vx_{i,j}^{ l^j (integer) }.
 */
KeyGenOutput keygen(TIACParams &params, int t, int n) {
    KeyGenOutput out;

    // EAKey dizisi
    out.eaKeys = new EAKey[n];

    // Polinom katsayıları
    // F[i] = new element_s[t+1], G[i] = new element_s[t+1]
    element_s **F = new element_s*[n];
    element_s **G = new element_s*[n];

    // 1) Rastgele polinom oluşturma
    for(int i=0; i<n; i++){
        F[i] = new element_s[t+1];
        G[i] = new element_s[t+1];

        for(int j=0; j<=t; j++){
            element_init_Zr(&F[i][j], params.pairing);
            element_random(&F[i][j]);

            element_init_Zr(&G[i][j], params.pairing);
            element_random(&G[i][j]);
        }
    }

    // 2) Commitments => Vx, Vy, Vy' (t+1 uzunluk)
    // EAKey’de pointer dizileri
    for(int i=0; i<n; i++){
        out.eaKeys[i].Vx = new element_t[t+1];
        out.eaKeys[i].Vy = new element_t[t+1];
        out.eaKeys[i].Vyprime = new element_t[t+1];

        for(int j=0; j<=t; j++){
            element_init_G2(out.eaKeys[i].Vx[j], params.pairing);
            element_init_G2(out.eaKeys[i].Vy[j], params.pairing);
            element_init_G1(out.eaKeys[i].Vyprime[j], params.pairing);

            // Vx_{i,j} = g2^( x_{i,j} )
            element_pow_zn(out.eaKeys[i].Vx[j], params.g2, &F[i][j]);
            // Vy_{i,j} = g2^( y_{i,j} )
            element_pow_zn(out.eaKeys[i].Vy[j], params.g2, &G[i][j]);
            // Vy'_{i,j} = g1^( y_{i,j} )
            element_pow_zn(out.eaKeys[i].Vyprime[j], params.g1, &G[i][j]);
        }
    }

    // 3) sabit terimler (x_{i0}, y_{i0})
    for(int i=0; i<n; i++){
        element_init_Zr(out.eaKeys[i].x0, params.pairing);
        element_set(out.eaKeys[i].x0, &F[i][0]);

        element_init_Zr(out.eaKeys[i].y0, params.pairing);
        element_set(out.eaKeys[i].y0, &G[i][0]);
    }

    // 4) Pay doğrulama
    //    g2^{F_i(L)} = ∏_{j=0..t} [ Vx[i][j] ^ (L^j) ] 
    //    g2^{G_i(L)} = ∏_{j=0..t} [ Vy[i][j] ^ (L^j) ] 
    //    g1^{G_i(L)} = ∏_{j=0..t} [ Vy'[i][j]^(L^j) ]
    //  DİKKAT: L^j (normal integer), bu yüzden element_pow_si(...) kullanıyoruz!
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

        for(int i=0; i<n; i++){
            for(int L=1; L<=n; L++){
                // F_i(L), G_i(L) mod r
                evaluatePoly(F[i], t, L, params, fVal);
                evaluatePoly(G[i], t, L, params, gVal);

                // lhs = g2^F_i(L)
                element_pow_zn(lhsG2, params.g2, fVal);

                // rhs = ∏_{j=0..t} ( Vx[i][j] ^ (L^j integer) )
                element_set1(rhsG2);
                long powInt = 1; // L^j (tam sayı)
                for(int j=0; j<=t; j++){
                    if(j>0) powInt *= L; // normal int çarpımı
                    element_t tmpG2;
                    element_init_G2(tmpG2, params.pairing);
                    // element_pow_si => integer exponent
                    element_pow_si(tmpG2, out.eaKeys[i].Vx[j], powInt);
                    element_mul(rhsG2, rhsG2, tmpG2);
                    element_clear(tmpG2);
                }

                if(element_cmp(lhsG2, rhsG2) != 0){
                    std::cerr << "[WARN] F_i("<<L<<") mismatch => i=" << i << "\n";
                }

                // g2^{ G_i(L) }
                element_pow_zn(lhsG2, params.g2, gVal);

                element_set1(rhsG2);
                powInt = 1;
                for(int j=0; j<=t; j++){
                    if(j>0) powInt *= L;
                    element_t tmpG2;
                    element_init_G2(tmpG2, params.pairing);
                    element_pow_si(tmpG2, out.eaKeys[i].Vy[j], powInt);
                    element_mul(rhsG2, rhsG2, tmpG2);
                    element_clear(tmpG2);
                }
                if(element_cmp(lhsG2, rhsG2) != 0){
                    std::cerr << "[WARN] G_i("<<L<<") mismatch G2 => i=" << i << "\n";
                }

                // g1^{ G_i(L) }
                element_t lhsG1temp;
                element_init_G1(lhsG1temp, params.pairing);
                element_pow_zn(lhsG1temp, params.g1, gVal);

                element_set1(rhsG1);
                powInt = 1;
                for(int j=0; j<=t; j++){
                    if(j>0) powInt *= L;
                    element_t tmpG1;
                    element_init_G1(tmpG1, params.pairing);
                    element_pow_si(tmpG1, out.eaKeys[i].Vyprime[j], powInt);
                    element_mul(rhsG1, rhsG1, tmpG1);
                    element_clear(tmpG1);
                }
                if(element_cmp(lhsG1temp, rhsG1) != 0){
                    std::cerr << "[WARN] G_i("<<L<<") mismatch G1 => i=" << i << "\n";
                }
                element_clear(lhsG1temp);
            }
        }

        element_clear(fVal);
        element_clear(gVal);
        element_clear(lhsG2);
        element_clear(rhsG2);
        element_clear(lhsG1);
        element_clear(rhsG1);
    }

    // 5) Master Verification Key (mvk) = ∏_{i=0..n-1} Vx[i][0], Vy[i][0], Vy'[i][0]
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

    // 6) Master Signing Key = ∑ F[i][0], ∑ G[i][0]
    element_init_Zr(out.msgk.sk1, params.pairing);
    element_init_Zr(out.msgk.sk2, params.pairing);
    element_set0(out.msgk.sk1);
    element_set0(out.msgk.sk2);

    for(int i=0; i<n; i++){
        element_add(out.msgk.sk1, out.msgk.sk1, &F[i][0]);
        element_add(out.msgk.sk2, out.msgk.sk2, &G[i][0]);
    }

    // 7) Local pay: sgk1, sgk2
    // sgk1 = ∑_{l=0..n-1} F[l](i+1),  sgk2 = ∑_{l=0..n-1} G[l](i+1)
    for(int i=0; i<n; i++){
        element_init_Zr(out.eaKeys[i].sgk1, params.pairing);
        element_init_Zr(out.eaKeys[i].sgk2, params.pairing);
        element_set0(out.eaKeys[i].sgk1);
        element_set0(out.eaKeys[i].sgk2);

        for(int L=0; L<n; L++){
            element_t valF, valG;
            element_init_Zr(valF, params.pairing);
            element_init_Zr(valG, params.pairing);

            evaluatePoly(F[L], t, i+1, params, valF);
            evaluatePoly(G[L], t, i+1, params, valG);
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

    // 8) Polinom bellek temizliği
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
