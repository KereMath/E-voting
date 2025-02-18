#include "keygen.h"
#include <pbc/pbc.h>
#include <gmp.h>
#include <vector>
#include <iostream>

// Yardımcı: Horner yöntemi ile polinom değerlendirmesi
// Katsayılar pointer listesi: std::vector<element_s*>
static void evaluatePoly(std::vector<element_s*> &coeff, int X, TIACParams &params, element_t result) {
    element_t X_val;
    element_init_Zr(X_val, params.pairing);
    element_set_si(X_val, X);
    
    // result = coeff[0]
    element_set(result, coeff[0]);
    for (size_t i = 1; i < coeff.size(); i++) {
        element_mul(result, result, X_val);
        element_add(result, result, coeff[i]);
    }
    element_clear(X_val);
}

KeyGenOutput keygen(TIACParams &params, int t, int ne) {
    KeyGenOutput output;
    
    // 1. F ve G polinom katsayıları için 2D vector (EA sayısı x t katsayısı)
    // Artık elemanlar, element_s* (yani pointer) olarak tutulacak.
    std::vector< std::vector<element_s*> > F_coeffs(ne), G_coeffs(ne);
    for (int i = 0; i < ne; i++) {
        F_coeffs[i].resize(t);
        G_coeffs[i].resize(t);
        for (int j = 0; j < t; j++) {
            // Yeni element_s için bellek ayırıyoruz
            F_coeffs[i][j] = new element_s;  
            element_init_Zr(F_coeffs[i][j], params.pairing);
            element_random(F_coeffs[i][j]);
            
            G_coeffs[i][j] = new element_s;
            element_init_Zr(G_coeffs[i][j], params.pairing);
            element_random(G_coeffs[i][j]);
        }
    }
    
    // 2. Master secret: msgk = (∏_{i=1}^{ne} F_i(0), ∏_{i=1}^{ne} G_i(0))
    element_t prod_F0, prod_G0;
    element_init_Zr(prod_F0, params.pairing);
    element_init_Zr(prod_G0, params.pairing);
    element_set1(prod_F0);
    element_set1(prod_G0);
    for (int i = 0; i < ne; i++) {
        // F_i(0) = F_coeffs[i][0], G_i(0) = G_coeffs[i][0]
        element_mul(prod_F0, prod_F0, F_coeffs[i][0]);
        element_mul(prod_G0, prod_G0, G_coeffs[i][0]);
    }
    
    // 3. Master verification key (mvk)
    // mvk.alpha2 = g1^(∏_{i} (F_i(0))^2)
    element_t temp;
    element_init_Zr(temp, params.pairing);
    element_set1(temp);
    for (int i = 0; i < ne; i++) {
        element_t square;
        element_init_Zr(square, params.pairing);
        element_mul(square, F_coeffs[i][0], F_coeffs[i][0]);
        element_mul(temp, temp, square);
        element_clear(square);
    }
    element_init_G1(output.mvk.alpha2, params.pairing);
    element_pow_zn(output.mvk.alpha2, params.g1, temp);
    
    // mvk.beta2 = g1^(∏_{i} (G_i(0))^2)
    element_set1(temp);
    for (int i = 0; i < ne; i++) {
        element_t square;
        element_init_Zr(square, params.pairing);
        element_mul(square, G_coeffs[i][0], G_coeffs[i][0]);
        element_mul(temp, temp, square);
        element_clear(square);
    }
    element_init_G1(output.mvk.beta2, params.pairing);
    element_pow_zn(output.mvk.beta2, params.g1, temp);
    
    // mvk.beta1 = g1^(∏_{i} G_i(0))
    element_init_G1(output.mvk.beta1, params.pairing);
    element_pow_zn(output.mvk.beta1, params.g1, prod_G0);
    
    element_clear(temp);
    element_clear(prod_F0);
    element_clear(prod_G0);
    
    // 4. Her EA için imza ve doğrulama anahtar paylarının üretimi.
    output.eaKeys.resize(ne);
    for (int i = 1; i <= ne; i++) {
        EAKey ea;
        element_t sgk1, sgk2;
        element_init_Zr(sgk1, params.pairing);
        element_set1(sgk1);
        element_init_Zr(sgk2, params.pairing);
        element_set1(sgk2);
        
        // Tüm EA'ların polinomlarını EA i için değerlendir (l = 0,..., ne-1)
        for (int l = 0; l < ne; l++) {
            element_t valF, valG;
            element_init_Zr(valF, params.pairing);
            element_init_Zr(valG, params.pairing);
            evaluatePoly(F_coeffs[l], i, params, valF);
            evaluatePoly(G_coeffs[l], i, params, valG);
            element_mul(sgk1, sgk1, valF);
            element_mul(sgk2, sgk2, valG);
            element_clear(valF);
            element_clear(valG);
        }
        // EA i için imza anahtar payı: sgk = (sgk1, sgk2)
        element_init_Zr(ea.sgk1, params.pairing);
        element_set(ea.sgk1, sgk1);
        element_init_Zr(ea.sgk2, params.pairing);
        element_set(ea.sgk2, sgk2);
        
        // vkm hesaplama: 
        // vkm1 = g1^(sgk1^2), vkm2 = g1^(sgk2^2), vkm3 = g1^(sgk2)
        element_t exp_val;
        element_init_Zr(exp_val, params.pairing);
        
        element_mul(exp_val, sgk1, sgk1);
        element_init_G1(ea.vkm1, params.pairing);
        element_pow_zn(ea.vkm1, params.g1, exp_val);
        
        element_mul(exp_val, sgk2, sgk2);
        element_init_G1(ea.vkm2, params.pairing);
        element_pow_zn(ea.vkm2, params.g1, exp_val);
        
        element_init_G1(ea.vkm3, params.pairing);
        element_pow_zn(ea.vkm3, params.g1, sgk2);
        
        element_clear(exp_val);
        element_clear(sgk1);
        element_clear(sgk2);
        
        output.eaKeys[i - 1] = ea;
    }
    
    // 5. Polinom katsayılarını serbest bırakma
    for (int i = 0; i < ne; i++) {
        for (int j = 0; j < t; j++) {
            element_clear(F_coeffs[i][j]);
            delete F_coeffs[i][j];
            element_clear(G_coeffs[i][j]);
            delete G_coeffs[i][j];
        }
    }
    
    return output;
}
