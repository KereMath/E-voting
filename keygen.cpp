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
    // Elemanlar element_s* olarak tutulacak.
    std::vector< std::vector<element_s*> > F_coeffs(ne), G_coeffs(ne);
    for (int i = 0; i < ne; i++) {
        F_coeffs[i].resize(t);
        G_coeffs[i].resize(t);
        for (int j = 0; j < t; j++) {
            F_coeffs[i][j] = new element_s;  
            element_init_Zr(F_coeffs[i][j], params.pairing);
            element_random(F_coeffs[i][j]);
            
            G_coeffs[i][j] = new element_s;
            element_init_Zr(G_coeffs[i][j], params.pairing);
            element_random(G_coeffs[i][j]);
        }
    }
    
    // 2. Master secret: msgk = (∏ F_i(0), ∏ G_i(0))
    element_t prod_F0, prod_G0;
    element_init_Zr(prod_F0, params.pairing);
    element_init_Zr(prod_G0, params.pairing);
    element_set1(prod_F0);
    element_set1(prod_G0);
    for (int i = 0; i < ne; i++) {
        element_mul(prod_F0, prod_F0, F_coeffs[i][0]);
        element_mul(prod_G0, prod_G0, G_coeffs[i][0]);
    }
    
    // 3. Master verification key (mvk)
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
    
    element_init_G1(output.mvk.beta1, params.pairing);
    element_pow_zn(output.mvk.beta1, params.g1, prod_G0);
    
    element_clear(temp);
    element_clear(prod_F0);
    element_clear(prod_G0);
    
    // 4. Her EA için imza ve doğrulama anahtar paylarının üretimi.
// 4. Her EA için imza ve doğrulama anahtar paylarının üretimi.
output.eaKeys.resize(ne);
for (int i = 1; i <= ne; i++) {
    EAKey ea;
    element_t sgk1, sgk2;
    element_init_Zr(sgk1, params.pairing);
    element_set1(sgk1);
    element_init_Zr(sgk2, params.pairing);
    element_set1(sgk2);
    
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
    element_init_Zr(ea.sgk1, params.pairing);
    element_set(ea.sgk1, sgk1);
    element_init_Zr(ea.sgk2, params.pairing);
    element_set(ea.sgk2, sgk2);
    
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
    
    // EA'nın kendi secret değerlerini (F₀ ve G₀) saklayalım.
    // F_coeffs[i-1][0] ve G_coeffs[i-1][0] zaten element_t (pointer) oldukları için doğrudan aktarabiliriz.
    element_init_Zr(ea.f0, params.pairing);
    element_set(ea.f0, F_coeffs[i-1][0]);
    
    element_init_Zr(ea.g0, params.pairing);
    element_set(ea.g0, G_coeffs[i-1][0]);
    
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



bu da maindeki keygen yeri

    // 4. Key Generation (Coconut TTP'siz / Pedersen's DKG)
    std::cout << "=== Coconut TTP'siz Anahtar Uretimi (Pedersen's DKG) ===\n";
    auto startKeygen = Clock::now();
    KeyGenOutput keyOut = keygen(params, t, ne);
    auto endKeygen = Clock::now();
    auto keygenDuration_us = std::chrono::duration_cast<std::chrono::microseconds>(endKeygen - startKeygen).count();
    
    // Master verification key çıktıları
    {
        char buffer[1024];
        element_snprintf(buffer, sizeof(buffer), "%B", keyOut.mvk.alpha2);
        std::cout << "mvk.alpha2 (g1^(∏ F_i(0)^2)) =\n" << buffer << "\n\n";
    }
    {
        char buffer[1024];
        element_snprintf(buffer, sizeof(buffer), "%B", keyOut.mvk.beta2);
        std::cout << "mvk.beta2 (g1^(∏ G_i(0)^2)) =\n" << buffer << "\n\n";
    }
    {
        char buffer[1024];
        element_snprintf(buffer, sizeof(buffer), "%B", keyOut.mvk.beta1);
        std::cout << "mvk.beta1 (g1^(∏ G_i(0))) =\n" << buffer << "\n\n";
    }
    
    // EA otoriteleri çıktıları
    for (int i = 0; i < ne; i++) {
        std::cout << "=== EA Authority " << (i + 1) << " ===\n";
        {
            char buffer[1024];
            element_snprintf(buffer, sizeof(buffer), "%B", keyOut.eaKeys[i].sgk1);
            std::cout << "sgk1 (∏_{l} F_l(" << (i+1) << ")) = " << buffer << "\n";
        }
        {
            char buffer[1024];
            element_snprintf(buffer, sizeof(buffer), "%B", keyOut.eaKeys[i].sgk2);
            std::cout << "sgk2 (∏_{l} G_l(" << (i+1) << ")) = " << buffer << "\n";
        }
        {
            char buffer[1024];
            element_snprintf(buffer, sizeof(buffer), "%B", keyOut.eaKeys[i].vkm1);
            std::cout << "vkm.alpha2 (g1^(sgk1^2)) = " << buffer << "\n";
        }
        {
            char buffer[1024];
            element_snprintf(buffer, sizeof(buffer), "%B", keyOut.eaKeys[i].vkm2);
            std::cout << "vkm.beta2 (g1^(sgk2^2)) = " << buffer << "\n";
        }
        {
            char buffer[1024];
            element_snprintf(buffer, sizeof(buffer), "%B", keyOut.eaKeys[i].vkm3);
            std::cout << "vkm.beta1 (g1^(sgk2)) = " << buffer << "\n";
        }
        std::cout << "\n";
    }
    
    std::cout << "Secmen sayisi: " << voterCount << "\n\n";

