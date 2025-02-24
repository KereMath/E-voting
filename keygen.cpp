#include "keygen.h"
#include <iostream>
#include <cassert>
#include <cmath>

/**
 * Değiştirilmiş Horner yöntemiyle polinom değerlendirme:
 * Fi(X) = x_{i0} + x_{i1}X + ... + x_{it}X^t
 *
 * coeffs boyutu = t+1
 */
static void evaluatePoly(const std::vector<element_t> &coeffs,
                         int X,
                         TIACParams &params,
                         element_t outVal)
{
    element_set0(outVal); // Zr'da 0
    element_t xVal;
    element_init_Zr(xVal, params.pairing);
    element_set_si(xVal, X);

    element_t power;
    element_init_Zr(power, params.pairing);
    element_set1(power);

    element_t tmp;
    element_init_Zr(tmp, params.pairing);

    for (size_t j = 0; j < coeffs.size(); j++) {
        // tmp = coeffs[j] * power
        element_mul(tmp, coeffs[j], power);
        element_add(outVal, outVal, tmp);

        // power *= xVal
        element_mul(power, power, xVal);
    }

    element_clear(xVal);
    element_clear(power);
    element_clear(tmp);
}

KeyGenOutput keygen(TIACParams &params, int t, int n) {
    KeyGenOutput result;
    result.eaKeys.resize(n);

    // Polinom katsayılarını saklayacağız:
    //  F_i(X) = x_{i0} + x_{i1}X + ... + x_{i,t}X^t
    //  G_i(X) = y_{i0} + y_{i1}X + ... + y_{i,t}X^t
    // T+1 katsayı
    std::vector< std::vector<element_t> > F_coeffs(n), G_coeffs(n);

    // Commitments:
    //  Vx_{i,j} = g2^( x_{i,j} )
    //  Vy_{i,j} = g2^( y_{i,j} )
    //  Vy'_{i,j} = g1^( y_{i,j} )
    // i in [0..n-1], j in [0..t] => (t+1) tane
    // (EA_i'ye ait polinom katsayılarına ait taahhütler)
    
    // 1) Rastgele katsayılar & commit
    for (int i=0; i<n; i++) {
        // t+1 uzunluğunda
        F_coeffs[i].resize(t+1);
        G_coeffs[i].resize(t+1);

        // EAKey üzerindeki vektörlere de t+1 yer açalım:
        result.eaKeys[i].Vx.resize(t+1);
        result.eaKeys[i].Vy.resize(t+1);
        result.eaKeys[i].Vyprime.resize(t+1);

        for (int j=0; j<=t; j++) {
            element_init_Zr(F_coeffs[i][j], params.pairing);
            element_random(F_coeffs[i][j]);

            element_init_Zr(G_coeffs[i][j], params.pairing);
            element_random(G_coeffs[i][j]);

            element_init_G2(result.eaKeys[i].Vx[j], params.pairing);
            element_init_G2(result.eaKeys[i].Vy[j], params.pairing);
            element_init_G1(result.eaKeys[i].Vyprime[j], params.pairing);

            // Vx[i][j] = g2^( x_{i,j} )
            element_pow_zn(result.eaKeys[i].Vx[j], params.g2, F_coeffs[i][j]);
            // Vy[i][j] = g2^( y_{i,j} )
            element_pow_zn(result.eaKeys[i].Vy[j], params.g2, G_coeffs[i][j]);
            // Vyprime[i][j] = g1^( y_{i,j} )
            element_pow_zn(result.eaKeys[i].Vyprime[j], params.g1, G_coeffs[i][j]);
        }
    }

    // 2) Her EA_i sabit terimi x_{i0}, y_{i0} => EAKey.x0, y0
    for (int i=0; i<n; i++) {
        element_init_Zr(result.eaKeys[i].x0, params.pairing);
        element_init_Zr(result.eaKeys[i].y0, params.pairing);
        element_set(result.eaKeys[i].x0, F_coeffs[i][0]);
        element_set(result.eaKeys[i].y0, G_coeffs[i][0]);
    }

    // 3) Pay dağıtma ve doğrulama (herkes doğru gönderiyor varsayımı).
    //    EAl => F_i(l), G_i(l). Kontrol: g2^(F_i(l)) = ∏_{j=0..t} Vx_{i,j}^( l^j ), vs.
    //    Aşağıda l = 1..n, i = 1..n. (disqualify yok)
    {
        element_t Fval, Gval;
        element_init_Zr(Fval, params.pairing);
        element_init_Zr(Gval, params.pairing);

        element_t lhs_g2, rhs_g2;
        element_init_G2(lhs_g2, params.pairing);
        element_init_G2(rhs_g2, params.pairing);

        element_t lhs_g1, rhs_g1;
        element_init_G1(lhs_g1, params.pairing);
        element_init_G1(rhs_g1, params.pairing);

        element_t powL;
        element_init_Zr(powL, params.pairing);

        for (int i=0; i<n; i++) {
            // i. EA'nın polinomuna bakıyoruz
            for (int l=1; l<=n; l++) {
                // F_i(l), G_i(l)
                evaluatePoly(F_coeffs[i], l, params, Fval);
                evaluatePoly(G_coeffs[i], l, params, Gval);

                //  -- Check 1: g2^(F_i(l)) ?= ∏ Vx_{i,j}^{ l^j }
                element_pow_zn(lhs_g2, params.g2, Fval);

                // RHS:
                element_set1(rhs_g2);
                element_set1(powL);
                for(int j=0; j<=t; j++) {
                    if(j>0) {
                        // powL *= l
                        element_mul_si(powL, powL, l);
                    }
                    // temp = Vx[i][j]^(powL)
                    element_t tempG2;
                    element_init_G2(tempG2, params.pairing);
                    element_pow_zn(tempG2, result.eaKeys[i].Vx[j], powL);
                    element_mul(rhs_g2, rhs_g2, tempG2);
                    element_clear(tempG2);
                }
                if(element_cmp(lhs_g2, rhs_g2) != 0) {
                    // Hatalı => complaint
                    std::cerr << "[uyumsuz F pay] i=" << i+1 << " l=" << l << "\n";
                }

                //  -- Check 2: g2^(G_i(l)) ?= ∏ Vy_{i,j}^{ l^j }
                element_pow_zn(lhs_g2, params.g2, Gval);
                element_set1(rhs_g2);
                element_set1(powL);
                for(int j=0; j<=t; j++) {
                    if(j>0) element_mul_si(powL, powL, l);
                    element_t tempG2;
                    element_init_G2(tempG2, params.pairing);
                    element_pow_zn(tempG2, result.eaKeys[i].Vy[j], powL);
                    element_mul(rhs_g2, rhs_g2, tempG2);
                    element_clear(tempG2);
                }
                if(element_cmp(lhs_g2, rhs_g2) != 0) {
                    std::cerr << "[uyumsuz G pay in G2] i=" << i+1 << " l=" << l << "\n";
                }

                //  -- Check 3: g1^(G_i(l)) ?= ∏ Vyprime_{i,j}^{ l^j }
                element_pow_zn(lhs_g1, params.g1, Gval);
                element_set1(rhs_g1);
                element_set1(powL);
                for(int j=0; j<=t; j++) {
                    if(j>0) element_mul_si(powL, powL, l);
                    element_t tempG1;
                    element_init_G1(tempG1, params.pairing);
                    element_pow_zn(tempG1, result.eaKeys[i].Vyprime[j], powL);
                    element_mul(rhs_g1, rhs_g1, tempG1);
                    element_clear(tempG1);
                }
                if(element_cmp(lhs_g1, rhs_g1) != 0) {
                    std::cerr << "[uyumsuz G pay in G1] i=" << i+1 << " l=" << l << "\n";
                }
            } // end-for(l)
        } // end-for(i)

        element_clear(Fval);
        element_clear(Gval);
        element_clear(lhs_g2);
        element_clear(rhs_g2);
        element_clear(lhs_g1);
        element_clear(rhs_g1);
        element_clear(powL);
    }

    // 4) Q = herkes (diskalifiye yok). 
    //    Master anahtarları:
    //    mvk = ( ∏ Vx_{i,0}, ∏ Vy_{i,0}, ∏ Vy'_{i,0} )
    //         = ( g2^( sum x_i0 ), g2^( sum y_i0 ), g1^( sum y_i0 ) )
    element_init_G2(result.mvk.vk1, params.pairing);
    element_init_G2(result.mvk.vk2, params.pairing);
    element_init_G1(result.mvk.vk3, params.pairing);

    element_set1(result.mvk.vk1);
    element_set1(result.mvk.vk2);
    element_set1(result.mvk.vk3);

    for (int i=0; i<n; i++) {
        // Vx_{i,0} = g2^(x_{i0}), Vy_{i,0} = g2^(y_{i0}), Vy'_{i,0} = g1^(y_{i0})
        // Aslında out.eaKeys[i].Vx[0], out.eaKeys[i].Vy[0], out.eaKeys[i].Vyprime[0]
        element_mul(result.mvk.vk1, result.mvk.vk1, result.eaKeys[i].Vx[0]);
        element_mul(result.mvk.vk2, result.mvk.vk2, result.eaKeys[i].Vy[0]);
        element_mul(result.mvk.vk3, result.mvk.vk3, result.eaKeys[i].Vyprime[0]);
    }

    // msgk = ( sk1, sk2 ) = ( sum x_{i0}, sum y_{i0} )
    element_init_Zr(result.msgk.sk1, params.pairing);
    element_init_Zr(result.msgk.sk2, params.pairing);
    element_set0(result.msgk.sk1);
    element_set0(result.msgk.sk2);

    for (int i=0; i<n; i++) {
        element_add(result.msgk.sk1, result.msgk.sk1, F_coeffs[i][0]);
        element_add(result.msgk.sk2, result.msgk.sk2, G_coeffs[i][0]);
    }

    // 5) Her EA_i için local imza payı:
    // sgk_i = ( ∑_{l in Q} F_l(i),  ∑_{l in Q} G_l(i) )
    // vki = ( g2^(sgk1), g2^(sgk2), g1^(sgk2) ).
    for (int i=0; i<n; i++){
        element_init_Zr(result.eaKeys[i].sgk1, params.pairing);
        element_init_Zr(result.eaKeys[i].sgk2, params.pairing);
        element_set0(result.eaKeys[i].sgk1);
        element_set0(result.eaKeys[i].sgk2);

        // Polinom değeri: i+1
        element_t valF, valG;
        element_init_Zr(valF, params.pairing);
        element_init_Zr(valG, params.pairing);

        for(int l=0; l<n; l++){
            evaluatePoly(F_coeffs[l], (i+1), params, valF);
            evaluatePoly(G_coeffs[l], (i+1), params, valG);
            element_add(result.eaKeys[i].sgk1, result.eaKeys[i].sgk1, valF);
            element_add(result.eaKeys[i].sgk2, result.eaKeys[i].sgk2, valG);
        }

        element_clear(valF);
        element_clear(valG);

        element_init_G2(result.eaKeys[i].vki1, params.pairing);
        element_init_G2(result.eaKeys[i].vki2, params.pairing);
        element_init_G1(result.eaKeys[i].vki3, params.pairing);

        element_pow_zn(result.eaKeys[i].vki1, params.g2, result.eaKeys[i].sgk1);
        element_pow_zn(result.eaKeys[i].vki2, params.g2, result.eaKeys[i].sgk2);
        element_pow_zn(result.eaKeys[i].vki3, params.g1, result.eaKeys[i].sgk2);
    }

    // 6) Polinom bellek temizliği
    for(int i=0; i<n; i++){
        for(int j=0; j<=t; j++){
            element_clear(F_coeffs[i][j]);
            element_clear(G_coeffs[i][j]);
        }
    }

    return result;
}
