#include "keygen.h"
#include <iostream>
#include <cassert>

/**
 * Polinom değerlendirme:
 * result = ∑_{k=0..(coeffs.size()-1)} ( coeffs[k] * X^k )
 * (Zr alanında)
 *
 * Burada coeffs[k] -> element_t*
 */
static void evaluatePoly(const std::vector<element_t*> &coeffs,
                         int X,
                         TIACParams &params,
                         element_t result)
{
    // Başlangıçta 0
    element_set0(result);

    // X değerini Zr içinde tutalım
    element_t xVal;
    element_init_Zr(xVal, params.pairing);
    element_set_si(xVal, X);

    // power = X^k
    element_t power;
    element_init_Zr(power, params.pairing);
    element_set1(power);

    // tmp = ara çarpımlar
    element_t tmp;
    element_init_Zr(tmp, params.pairing);

    for (size_t i = 0; i < coeffs.size(); i++) {
        // tmp = coeffs[i] * power
        // coeffs[i]  -> element_t*
        element_mul(tmp, coeffs[i], power);
        // result += tmp
        element_add(result, result, tmp);

        // power *= xVal
        element_mul(power, power, xVal);
    }

    element_clear(xVal);
    element_clear(power);
    element_clear(tmp);
}

/**
 * Pedersen’s DKG: Her EA_i kendi F_i(X), G_i(X) polinomunu oluşturur.
 * Tüm paylar doğrulanabilir, kimse hata yapmadıysa
 * Master key ve EA payları oluşturulur.
 */
KeyGenOutput keygen(TIACParams &params, int t, int n) {
    KeyGenOutput out;
    out.eaKeys.resize(n);

    // Polinom katsayılarını pointer olarak saklayacağız:
    // F_coeffs[i][j], G_coeffs[i][j] => element_t*
    // i: EA index, j: 0..t-1 (katsayı)
    std::vector< std::vector<element_t*> > F_coeffs(n), G_coeffs(n);

    // 1) Alloc + init + random
    for(int i=0; i<n; i++){
        F_coeffs[i].resize(t);
        G_coeffs[i].resize(t);
        for(int j=0; j<t; j++){
            // F(i,j)
            F_coeffs[i][j] = new element_s; // bellek ayır
            element_init_Zr(F_coeffs[i][j], params.pairing);
            element_random(F_coeffs[i][j]);

            // G(i,j)
            G_coeffs[i][j] = new element_s;
            element_init_Zr(G_coeffs[i][j], params.pairing);
            element_random(G_coeffs[i][j]);
        }
    }

    // 2) Her EA_i sabit terimini (x_i0, y_i0) saklasın
    //    -> out.eaKeys[i].x_m, y_m
    for (int i=0; i<n; i++){
        element_init_Zr(out.eaKeys[i].x_m, params.pairing);
        element_init_Zr(out.eaKeys[i].y_m, params.pairing);
        element_set(out.eaKeys[i].x_m, F_coeffs[i][0]);
        element_set(out.eaKeys[i].y_m, G_coeffs[i][0]);
    }

    // 3) Master secret key (msk) = ( ∑ x_i0, ∑ y_i0 )
    element_init_Zr(out.msk.sk1, params.pairing);
    element_init_Zr(out.msk.sk2, params.pairing);
    element_set0(out.msk.sk1);
    element_set0(out.msk.sk2);

    for (int i=0; i<n; i++){
        element_add(out.msk.sk1, out.msk.sk1, F_coeffs[i][0]); // x_i0
        element_add(out.msk.sk2, out.msk.sk2, G_coeffs[i][0]); // y_i0
    }

    // 4) Master verification key (mvk) = (g2^sum(x_i0), g2^sum(y_i0), g1^sum(y_i0))
    element_init_G2(out.mvk.vk1, params.pairing);
    element_init_G2(out.mvk.vk2, params.pairing);
    element_init_G1(out.mvk.vk3, params.pairing);

    element_pow_zn(out.mvk.vk1, params.g2, out.msk.sk1);
    element_pow_zn(out.mvk.vk2, params.g2, out.msk.sk2);
    element_pow_zn(out.mvk.vk3, params.g1, out.msk.sk2);

    // 5) Her EA_i için local pay: sgk1, sgk2
    //    sgk1 = ∑_{l=0..n-1} F_l(i+1)
    //    sgk2 = ∑_{l=0..n-1} G_l(i+1)
    //    vki1 = g2^sgk1, vki2 = g2^sgk2, vki3 = g1^sgk2
    for (int i=0; i<n; i++){
        element_init_Zr(out.eaKeys[i].sgk1, params.pairing);
        element_init_Zr(out.eaKeys[i].sgk2, params.pairing);
        element_set0(out.eaKeys[i].sgk1);
        element_set0(out.eaKeys[i].sgk2);

        element_t tmpF, tmpG;
        element_init_Zr(tmpF, params.pairing);
        element_init_Zr(tmpG, params.pairing);

        for (int l=0; l<n; l++){
            // evaluatePoly(F_l, X=i+1)
            evaluatePoly(F_coeffs[l], i+1, params, tmpF);
            evaluatePoly(G_coeffs[l], i+1, params, tmpG);

            element_add(out.eaKeys[i].sgk1, out.eaKeys[i].sgk1, tmpF);
            element_add(out.eaKeys[i].sgk2, out.eaKeys[i].sgk2, tmpG);
        }
        element_clear(tmpF);
        element_clear(tmpG);

        // Doğrulama payları
        element_init_G2(out.eaKeys[i].vki1, params.pairing);
        element_init_G2(out.eaKeys[i].vki2, params.pairing);
        element_init_G1(out.eaKeys[i].vki3, params.pairing);

        element_pow_zn(out.eaKeys[i].vki1, params.g2, out.eaKeys[i].sgk1);
        element_pow_zn(out.eaKeys[i].vki2, params.g2, out.eaKeys[i].sgk2);
        element_pow_zn(out.eaKeys[i].vki3, params.g1, out.eaKeys[i].sgk2);
    }

    // 6) Bellek temizliği
    //    Polinom katsayılarını clear + delete
    for (int i=0; i<n; i++){
        for (int j=0; j<t; j++){
            element_clear(F_coeffs[i][j]);
            delete F_coeffs[i][j];
            element_clear(G_coeffs[i][j]);
            delete G_coeffs[i][j];
        }
    }

    return out;
}
