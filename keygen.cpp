#include "keygen.h"
#include <iostream>
#include <cassert>

/**
 * Polinom değerlendirme:
 * result = ∑ ( coeffs[k] * X^k )
 * 
 * Burada coeffs[k] = element_t* (pointer).
 * Fonksiyona girmeden once outVal init edilmeli.
 */
static void evaluatePoly(const std::vector<element_t*> &coeffs,
                         int X,
                         TIACParams &params,
                         element_t outVal)
{
    element_set0(outVal);

    // X değerini Zr içinde tut
    element_t xVal;
    element_init_Zr(xVal, params.pairing);
    element_set_si(xVal, X);

    // power = X^k
    element_t power;
    element_init_Zr(power, params.pairing);
    element_set1(power);

    // tmp
    element_t tmp;
    element_init_Zr(tmp, params.pairing);

    for (size_t k = 0; k < coeffs.size(); k++) {
        // tmp = (*coeffs[k]) * power
        // coeffs[k] -> element_t*
        element_mul(tmp, *coeffs[k], power);
        element_add(outVal, outVal, tmp);

        // power *= xVal
        element_mul(power, power, xVal);
    }

    element_clear(xVal);
    element_clear(power);
    element_clear(tmp);
}

/**
 * Pedersen’s DKG: 
 * - Her EA_i => polinom katsayıları F_i(X), G_i(X) 
 * - Commitment hesapları (Vx, Vy, Vy')
 * - Pay dağıtımı & basit doğrulama 
 * - Tüm EA'lar geçerli olduğu varsayılıyor (şikayet yok)
 * - Master anahtar (mvk, msgk) ve local paylar (sgk, vki)
 */
KeyGenOutput keygen(TIACParams &params, int t, int n) {
    KeyGenOutput out;
    out.eaKeys.resize(n);

    // Polinom katsayıları pointer olarak tutacağız:
    // F_coeffs[i][j], G_coeffs[i][j] => element_t*
    // i in [0..n-1], j in [0..t] => (t+1) katsayı
    std::vector< std::vector<element_t*> > F_coeffs(n), G_coeffs(n);

    // 1) Rastgele polinom katsayıları seç + commitment
    //    EAKey’de Vx, Vy, Vyprime (t+1 her biri)
    for(int i = 0; i < n; i++){
        // i. EA polinomları: boyut t+1
        F_coeffs[i].resize(t+1);
        G_coeffs[i].resize(t+1);

        // EAKey’de de vektörleri açalım
        out.eaKeys[i].Vx.resize(t+1);
        out.eaKeys[i].Vy.resize(t+1);
        out.eaKeys[i].Vyprime.resize(t+1);

        for(int j = 0; j <= t; j++){
            // Bellek ayırma
            F_coeffs[i][j] = new element_s;
            G_coeffs[i][j] = new element_s;

            // Init Zr
            element_init_Zr(F_coeffs[i][j], params.pairing);
            element_init_Zr(G_coeffs[i][j], params.pairing);

            // Rastgele
            element_random(F_coeffs[i][j]);
            element_random(G_coeffs[i][j]);

            // EAKey’deki commitments init
            element_init_G2(out.eaKeys[i].Vx[j], params.pairing);
            element_init_G2(out.eaKeys[i].Vy[j], params.pairing);
            element_init_G1(out.eaKeys[i].Vyprime[j], params.pairing);

            // Vx_{i,j} = g2^(x_{i,j})
            element_pow_zn(out.eaKeys[i].Vx[j], params.g2, *F_coeffs[i][j]);
            // Vy_{i,j} = g2^(y_{i,j})
            element_pow_zn(out.eaKeys[i].Vy[j], params.g2, *G_coeffs[i][j]);
            // Vy'_{i,j}= g1^(y_{i,j})
            element_pow_zn(out.eaKeys[i].Vyprime[j], params.g1, *G_coeffs[i][j]);
        }
    }

    // 2) Sabit katsayılar (x_{i0}, y_{i0}) => EAKey.x0, y0
    for(int i=0; i<n; i++){
        element_init_Zr(out.eaKeys[i].x0, params.pairing);
        element_init_Zr(out.eaKeys[i].y0, params.pairing);
        element_set(out.eaKeys[i].x0, *F_coeffs[i][0]);
        element_set(out.eaKeys[i].y0, *G_coeffs[i][0]);
    }

    // 3) Pay dağıtımı ve doğrulama (şikayetsiz)
    {
        // LHS ve RHS kıyaslamalarında kullanacağımız geçici alanlar
        element_t fVal, gVal;
        element_init_Zr(fVal, params.pairing);
        element_init_Zr(gVal, params.pairing);

        element_t lhsG2, rhsG2;
        element_init_G2(lhsG2, params.pairing);
        element_init_G2(rhsG2, params.pairing);

        element_t lhsG1, rhsG1;
        element_init_G1(lhsG1, params.pairing);
        element_init_G1(rhsG1, params.pairing);

        element_t lPow;
        element_init_Zr(lPow, params.pairing);

        // i => polinom sahibi, l => payı alan EA
        for(int i=0; i<n; i++){
            for(int l=1; l<=n; l++){
                // F_i(l)
                evaluatePoly(F_coeffs[i], l, params, fVal);
                // G_i(l)
                evaluatePoly(G_coeffs[i], l, params, gVal);

                // Check1: g2^{F_i(l)} =? ∏ Vx[i][j]^(l^j)
                element_pow_zn(lhsG2, params.g2, fVal);

                element_set1(rhsG2);
                element_set1(lPow);

                for(int j=0; j<=t; j++){
                    if(j>0){
                        // lPow *= l
                        element_mul_si(lPow, lPow, l);
                    }
                    // tmp = Vx[i][j]^(lPow)
                    element_t tmpG2;
                    element_init_G2(tmpG2, params.pairing);
                    element_pow_zn(tmpG2, out.eaKeys[i].Vx[j], lPow);

                    element_mul(rhsG2, rhsG2, tmpG2);
                    element_clear(tmpG2);
                }
                if(element_cmp(lhsG2, rhsG2) != 0){
                    std::cerr << "[WARN] F_i(l) pay tutarsız! i=" << i+1 << ", l=" << l << "\n";
                }

                // Check2: g2^{G_i(l)} =? ∏ Vy[i][j]^(l^j)
                element_pow_zn(lhsG2, params.g2, gVal);

                element_set1(rhsG2);
                element_set1(lPow);
                for(int j=0; j<=t; j++){
                    if(j>0) element_mul_si(lPow, lPow, l);
                    element_t tmpG2;
                    element_init_G2(tmpG2, params.pairing);
                    element_pow_zn(tmpG2, out.eaKeys[i].Vy[j], lPow);
                    element_mul(rhsG2, rhsG2, tmpG2);
                    element_clear(tmpG2);
                }
                if(element_cmp(lhsG2, rhsG2) != 0){
                    std::cerr << "[WARN] G_i(l) pay tutarsız (G2)! i=" << i+1 << ", l=" << l << "\n";
                }

                // Check3: g1^{G_i(l)} =? ∏ Vyprime[i][j]^(l^j)
                element_pow_zn(lhsG1, params.g1, gVal);

                element_set1(rhsG1);
                element_set1(lPow);
                for(int j=0; j<=t; j++){
                    if(j>0) element_mul_si(lPow, lPow, l);
                    element_t tmpG1;
                    element_init_G1(tmpG1, params.pairing);
                    element_pow_zn(tmpG1, out.eaKeys[i].Vyprime[j], lPow);
                    element_mul(rhsG1, rhsG1, tmpG1);
                    element_clear(tmpG1);
                }
                if(element_cmp(lhsG1, rhsG1) != 0){
                    std::cerr << "[WARN] G_i(l) pay tutarsız (G1)! i=" << i+1 << ", l=" << l << "\n";
                }
            }
        }
        element_clear(fVal);
        element_clear(gVal);
        element_clear(lhsG2);
        element_clear(rhsG2);
        element_clear(lhsG1);
        element_clear(rhsG1);
        element_clear(lPow);
    }

    // 4) Q = tüm EA’ler (kimse diskalifiye edilmedi).
    // mvk = ( ∏ Vx_{i,0}, ∏ Vy_{i,0}, ∏ Vy'_{i,0} )
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

    // 5) Master signing key (msgk) = ( ∑ x_{i0}, ∑ y_{i0} )
    element_init_Zr(out.msgk.sk1, params.pairing);
    element_init_Zr(out.msgk.sk2, params.pairing);
    element_set0(out.msgk.sk1);
    element_set0(out.msgk.sk2);

    for(int i=0; i<n; i++){
        element_add(out.msgk.sk1, out.msgk.sk1, *F_coeffs[i][0]);
        element_add(out.msgk.sk2, out.msgk.sk2, *G_coeffs[i][0]);
    }

    // 6) Her EA_i => local signing key share: sgk1 = ∑ F_l(i+1), sgk2 = ∑ G_l(i+1)
    //     vki = ( g2^sgk1, g2^sgk2, g1^sgk2 )
    for(int i=0; i<n; i++){
        element_init_Zr(out.eaKeys[i].sgk1, params.pairing);
        element_init_Zr(out.eaKeys[i].sgk2, params.pairing);
        element_set0(out.eaKeys[i].sgk1);
        element_set0(out.eaKeys[i].sgk2);

        element_t tempF, tempG;
        element_init_Zr(tempF, params.pairing);
        element_init_Zr(tempG, params.pairing);

        for(int l=0; l<n; l++){
            // F_l(i+1), G_l(i+1)
            evaluatePoly(F_coeffs[l], i+1, params, tempF);
            evaluatePoly(G_coeffs[l], i+1, params, tempG);
            element_add(out.eaKeys[i].sgk1, out.eaKeys[i].sgk1, tempF);
            element_add(out.eaKeys[i].sgk2, out.eaKeys[i].sgk2, tempG);
        }
        element_clear(tempF);
        element_clear(tempG);

        element_init_G2(out.eaKeys[i].vki1, params.pairing);
        element_init_G2(out.eaKeys[i].vki2, params.pairing);
        element_init_G1(out.eaKeys[i].vki3, params.pairing);

        element_pow_zn(out.eaKeys[i].vki1, params.g2, out.eaKeys[i].sgk1);
        element_pow_zn(out.eaKeys[i].vki2, params.g2, out.eaKeys[i].sgk2);
        element_pow_zn(out.eaKeys[i].vki3, params.g1, out.eaKeys[i].sgk2);
    }

    // 7) Bellek temizliği: polinom katsayılarını clear + delete
    for(int i=0; i<n; i++){
        for(int j=0; j<=t; j++){
            element_clear(F_coeffs[i][j]);
            delete F_coeffs[i][j];
            element_clear(G_coeffs[i][j]);
            delete G_coeffs[i][j];
        }
    }

    return out;
}
