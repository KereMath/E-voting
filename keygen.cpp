#include "keygen.h"
#include <iostream>
#include <cassert>
#include <cmath>

/**
 * Yardımcı fonksiyon: F_i(l) = ∑_{j=0..t-1} x_{ij} * l^j  (Zr üzerinde)
 */
static void evaluatePoly(const std::vector<element_t> &coeffs,
                         int l, // hangi noktada değerlenecek
                         const TIACParams &params,
                         element_t outVal)
{
    // outVal = coeffs[0] + coeffs[1]*l + coeffs[2]*l^2 + ...
    element_set0(outVal); // Zr alanında 0
    element_t term, tmpL;
    element_init_Zr(term, params.pairing);
    element_init_Zr(tmpL, params.pairing);

    // tmpL = l (int değerden Zr'ye)
    element_set_si(tmpL, l);

    // Horner yöntemi de kullanılabilir, ancak basit açık form:
    element_t powerOfL;
    element_init_Zr(powerOfL, params.pairing);
    element_set1(powerOfL); // l^0 = 1

    for (size_t j = 0; j < coeffs.size(); j++) {
        // term = coeffs[j] * powerOfL
        element_mul(term, coeffs[j], powerOfL);
        // outVal += term
        element_add(outVal, outVal, term);

        // powerOfL *= l
        element_mul(powerOfL, powerOfL, tmpL);
    }

    element_clear(term);
    element_clear(tmpL);
    element_clear(powerOfL);
}

/**
 * KeyGen: Pedersen’s DKG süreci (şikayetsiz, diskalifiye yok)
 */
KeyGenOutput keygen(TIACParams &params, int t, int n) {
    KeyGenOutput result;
    result.eaKeys.resize(n);

    // t-1 dereceli polinom: Fi(X) = xi0 + xi1*X + ... + xi(t-1)*X^(t-1)
    //                        Gi(X) = yi0 + yi1*X + ... + yi(t-1)*X^(t-1)
    // Her EA_i, bu iki polinomu oluşturacak. Sonra commitments.
    // Tersine: t parametreniz polinomun kaç tane katsayısı olduğunu belirler (derece = t-1).

    int polyDegree = t - 1;
    if (polyDegree < 0) {
        std::cerr << "[HATA] Eşik degeri t >= 1 olmalı!\n";
        // Geri dönüş ya da assert...
    }

    // -- Polinom katsayılarını tutacak yapı: F[i][j], G[i][j]
    // i: hangi EA (0..n-1), j: katsayı index (0..t-1)
    std::vector< std::vector<element_t> > F_coeffs(n), G_coeffs(n);

    // Commitments: Vx[i][j], Vy[i][j], VyPrime[i][j]
    // i: EA_i, j: 0..polyDegree
    // Vx[i][j] = g2^( x_{ij} ), Vy[i][j] = g2^( y_{ij} ), VyPrime[i][j] = g1^( y_{ij} )
    std::vector< std::vector<element_t> > Vx(n), Vy(n), VyPrime(n);

    for(int i=0; i<n; i++){
        F_coeffs[i].resize(t);
        G_coeffs[i].resize(t);
        Vx[i].resize(t);
        Vy[i].resize(t);
        VyPrime[i].resize(t);

        for(int j=0; j<t; j++){
            element_init_Zr(F_coeffs[i][j], params.pairing);
            element_init_Zr(G_coeffs[i][j], params.pairing);

            element_init_G2(Vx[i][j], params.pairing);
            element_init_G2(Vy[i][j], params.pairing);
            element_init_G1(VyPrime[i][j], params.pairing);

            // Rastgele katsayı seç
            element_random(F_coeffs[i][j]);
            element_random(G_coeffs[i][j]);

            // Commitments
            // Vx[i][j] = g2^( F_coeffs[i][j] ) = g2^( x_{ij} )
            element_pow_zn(Vx[i][j], params.g2, F_coeffs[i][j]);
            // Vy[i][j] = g2^( G_coeffs[i][j] ) = g2^( y_{ij} )
            element_pow_zn(Vy[i][j], params.g2, G_coeffs[i][j]);
            // VyPrime[i][j] = g1^( y_{ij} )
            element_pow_zn(VyPrime[i][j], params.g1, G_coeffs[i][j]);
        }
    }

    // -- 2. Her EA_i sabit terimleri (x_{i0}, y_{i0}) saklasın (ileride de kullanabilmek için)
    //    x_{i0}, y_{i0} => polinomun 0. katsayıları
    for (int i = 0; i < n; i++) {
        element_init_Zr(result.eaKeys[i].x_m, params.pairing);
        element_init_Zr(result.eaKeys[i].y_m, params.pairing);
        element_set(result.eaKeys[i].x_m, F_coeffs[i][0]);
        element_set(result.eaKeys[i].y_m, G_coeffs[i][0]);
    }

    // -- 3. Pay Dagitimi ve Dogrulama (basitleştirilmiş):
    //    EA_i -> EA_l : (F_i(l), G_i(l)) yolluyor.
    //    EA_l, commitments ile kontrol ediyor:
    //        g2^{F_i(l)}  == ∏_{j=0..polyDegree} [Vx[i][j]]^( l^j )
    //        g2^{G_i(l)}  == ∏_{j=0..polyDegree} [Vy[i][j]]^( l^j )
    //        g1^{G_i(l)}  == ∏_{j=0..polyDegree} [VyPrime[i][j]]^( l^j )
    //
    // Biz burada hepsinin doğru olduğunu varsayıyoruz. Ama yine de hesaplayıp check edebiliriz.
    // Kimse diskalifiye edilmediğini varsayalım: Q = {1..n}.

    element_t F_val, G_val;
    element_init_Zr(F_val, params.pairing);
    element_init_Zr(G_val, params.pairing);

    element_t lhs_G2, rhs_G2, rhs_G1;
    element_init_G2(lhs_G2, params.pairing);
    element_init_G2(rhs_G2, params.pairing);
    element_init_G2(rhs_G1, params.pairing); // Bu aslında G1 elemanı değil, isme dikkat ama G2 type init var! 
    // (Bu satıra dikkat, G1 e bakmamız lazım. Aşağıda g1^{G_i(l)} kontrolü yaparken G1 init edilecek.)
    // Kodda isim karışıklığı olmaması için rhs_G1 elemanını G1 tipinde init edelim:

    element_clear(rhs_G1);
    element_init_G1(rhs_G1, params.pairing);

    // Tüm i,l çiftleri için:
    for(int i=0; i<n; i++){
        for(int l=1; l<=n; l++){
            // 1) F_i(l) ve G_i(l) hesapla
            evaluatePoly(F_coeffs[i], l, params, F_val);
            evaluatePoly(G_coeffs[i], l, params, G_val);

            // 2) LHS: g2^{F_i(l)} ve g2^{G_i(l)}
            element_pow_zn(lhs_G2, params.g2, F_val);

            // 3) RHS: ∏_{j=0..polyDegree} Vx[i][j]^( l^j )
            element_set1(rhs_G2); 
            element_t lPow;
            element_init_Zr(lPow, params.pairing);
            element_set1(lPow);

            for(int j=0; j<t; j++){
                // l^j
                if(j>0) {
                    // lPow *= l
                    element_mul_si(lPow, lPow, l);
                }
                element_t tempG2;
                element_init_G2(tempG2, params.pairing);
                element_pow_zn(tempG2, Vx[i][j], lPow);
                element_mul(rhs_G2, rhs_G2, tempG2);
                element_clear(tempG2);
            }

            // Check
            if(element_cmp(lhs_G2, rhs_G2) != 0){
                std::cerr << "[Uyumsuzluk] F_i(l) pay dogrulanamadi. i=" << i << ", l=" << l << "\n";
                // normalde complaint, diskalifiye vb...
            }

            // Aynısını G_i(l) için
            element_pow_zn(lhs_G2, params.g2, G_val); // g2^{G_i(l)}
            element_set1(rhs_G2); 
            element_set1(lPow);
            for(int j=0; j<t; j++){
                if(j>0) element_mul_si(lPow, lPow, l);
                element_t tempG2;
                element_init_G2(tempG2, params.pairing);
                element_pow_zn(tempG2, Vy[i][j], lPow);
                element_mul(rhs_G2, rhs_G2, tempG2);
                element_clear(tempG2);
            }
            if(element_cmp(lhs_G2, rhs_G2) != 0){
                std::cerr << "[Uyumsuzluk] G_i(l) pay dogrulanamadi (g2). i=" << i << ", l=" << l << "\n";
            }

            // Ve g1^{G_i(l)} kontrolü
            element_t lhs_G1;
            element_init_G1(lhs_G1, params.pairing);
            element_pow_zn(lhs_G1, params.g1, G_val);

            element_set1(rhs_G1);
            element_set1(lPow);
            for(int j=0; j<t; j++){
                if(j>0) element_mul_si(lPow, lPow, l);
                element_t tempG1;
                element_init_G1(tempG1, params.pairing);
                element_pow_zn(tempG1, VyPrime[i][j], lPow);
                element_mul(rhs_G1, rhs_G1, tempG1);
                element_clear(tempG1);
            }
            if(element_cmp(lhs_G1, rhs_G1) != 0){
                std::cerr << "[Uyumsuzluk] G_i(l) pay dogrulanamadi (g1). i=" << i << ", l=" << l << "\n";
            }
            element_clear(lhs_G1);
            element_clear(lPow);
        }
    }

    element_clear(F_val);
    element_clear(G_val);
    element_clear(lhs_G2);
    element_clear(rhs_G2);
    element_clear(rhs_G1);

    // -- 4. Q = tüm EA'ler (diskalifiye yok). Artık Master Anahtarlarını oluşturuyoruz.
    // Master secret key (msgk) = (sk1, sk2) = ( ∑ x_i0, ∑ y_i0 )  [i in Q]
    element_init_Zr(result.msk.sk1, params.pairing);
    element_init_Zr(result.msk.sk2, params.pairing);
    element_set0(result.msk.sk1);
    element_set0(result.msk.sk2);

    for(int i=0; i<n; i++){
        element_add(result.msk.sk1, result.msk.sk1, F_coeffs[i][0]); // x_{i0}
        element_add(result.msk.sk2, result.msk.sk2, G_coeffs[i][0]); // y_{i0}
    }

    // Master verification key (mvk) = ( ∏ g2^{x_i0}, ∏ g2^{y_i0}, ∏ g1^{y_i0} )
    // = (g2^X, g2^Y, g1^Y)  (X = ∑ x_i0, Y = ∑ y_i0)
    element_init_G2(result.mvk.vk1, params.pairing);
    element_init_G2(result.mvk.vk2, params.pairing);
    element_init_G1(result.mvk.vk3, params.pairing);

    // mvk.vk1 = g2^{(sum x_i0)}
    element_pow_zn(result.mvk.vk1, params.g2, result.msk.sk1);
    // mvk.vk2 = g2^{(sum y_i0)}
    element_pow_zn(result.mvk.vk2, params.g2, result.msk.sk2);
    // mvk.vk3 = g1^{(sum y_i0)}
    element_pow_zn(result.mvk.vk3, params.g1, result.msk.sk2);

    // -- 5. Her EA için local paylar:
    // sgk_i = ( ∑ F_l(i), ∑ G_l(i) )  for l in Q
    // vki = (g2^(sgk_i1), g2^(sgk_i2), g1^(sgk_i2))
    for (int i = 0; i < n; i++){
        element_init_Zr(result.eaKeys[i].sgk1, params.pairing);
        element_init_Zr(result.eaKeys[i].sgk2, params.pairing);
        element_set0(result.eaKeys[i].sgk1);
        element_set0(result.eaKeys[i].sgk2);

        // ∑_{l=1..n} F_l(i) ve G_l(i):
        element_t valF, valG;
        element_init_Zr(valF, params.pairing);
        element_init_Zr(valG, params.pairing);

        for(int l = 0; l < n; l++){
            evaluatePoly(F_coeffs[l], i+1, params, valF); // i+1 çünkü EA_i => X = i+1
            evaluatePoly(G_coeffs[l], i+1, params, valG);
            element_add(result.eaKeys[i].sgk1, result.eaKeys[i].sgk1, valF);
            element_add(result.eaKeys[i].sgk2, result.eaKeys[i].sgk2, valG);
        }
        element_clear(valF);
        element_clear(valG);

        // vki1 = g2^(sgk1), vki2 = g2^(sgk2), vki3 = g1^(sgk2)
        element_init_G2(result.eaKeys[i].vki1, params.pairing);
        element_init_G2(result.eaKeys[i].vki2, params.pairing);
        element_init_G1(result.eaKeys[i].vki3, params.pairing);

        element_pow_zn(result.eaKeys[i].vki1, params.g2, result.eaKeys[i].sgk1);
        element_pow_zn(result.eaKeys[i].vki2, params.g2, result.eaKeys[i].sgk2);
        element_pow_zn(result.eaKeys[i].vki3, params.g1, result.eaKeys[i].sgk2);
    }

    // -- 6. Polinom katsayılarını bellekten temizle
    for(int i=0; i<n; i++){
        for(int j=0; j<t; j++){
            element_clear(F_coeffs[i][j]);
            element_clear(G_coeffs[i][j]);
            element_clear(Vx[i][j]);
            element_clear(Vy[i][j]);
            element_clear(VyPrime[i][j]);
        }
    }

    return result;
}
