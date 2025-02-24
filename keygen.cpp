#include "keygen.h"
#include <pbc/pbc.h>
#include <gmp.h>
#include <vector>
#include <iostream>

// Yardımcı: Horner yöntemi ile polinom değerlendirmesi
static void evaluatePoly(const std::vector<element_t>& coeff, int X, TIACParams &params, element_t result) {
    element_t X_val;
    element_init_Zr(X_val, params.pairing);
    element_set_si(X_val, X);
    
    element_set(result, coeff[0]);
    for (size_t i = 1; i < coeff.size(); i++) {
        element_mul(result, result, X_val);
        element_add(result, result, coeff[i]);
    }
    element_clear(X_val);
}

KeyGenOutput keygen(TIACParams &params, int t, int ne) {
    KeyGenOutput output;
    
    // 1. F ve G polinom katsayıları ve commitmentlar için vektorler
    std::vector<std::vector<element_t>> F_coeffs(ne);
    std::vector<std::vector<element_t>> G_coeffs(ne);
    std::vector<std::vector<element_t>> Vx(ne);  // g2^xij commitments
    std::vector<std::vector<element_t>> Vy(ne);  // g2^yij commitments
    std::vector<std::vector<element_t>> Vy_prime(ne);  // g1^yij commitments
    
    // Initialize vectors
    for (int i = 0; i < ne; i++) {
        F_coeffs[i].resize(t);
        G_coeffs[i].resize(t);
        Vx[i].resize(t);
        Vy[i].resize(t);
        Vy_prime[i].resize(t);
        
        for (int j = 0; j < t; j++) {
            // Initialize polynomial coefficients
            element_init_Zr(F_coeffs[i][j], params.pairing);
            element_init_Zr(G_coeffs[i][j], params.pairing);
            element_random(F_coeffs[i][j]);
            element_random(G_coeffs[i][j]);
            
            // Initialize and compute commitments
            element_init_G2(Vx[i][j], params.pairing);
            element_init_G2(Vy[i][j], params.pairing);
            element_init_G1(Vy_prime[i][j], params.pairing);
            
            element_pow_zn(Vx[i][j], params.g2, F_coeffs[i][j]);
            element_pow_zn(Vy[i][j], params.g2, G_coeffs[i][j]);
            element_pow_zn(Vy_prime[i][j], params.g1, G_coeffs[i][j]);
        }
    }
    
    // 2. Verify shares
    std::vector<bool> disqualified(ne, false);
    for (int i = 0; i < ne; i++) {
        for (int l = 0; l < ne; l++) {
            if (i == l) continue;
            
            // Compute F_l(i) and G_l(i)
            element_t Fi, Gi;
            element_init_Zr(Fi, params.pairing);
            element_init_Zr(Gi, params.pairing);
            evaluatePoly(F_coeffs[l], i+1, params, Fi);
            evaluatePoly(G_coeffs[l], i+1, params, Gi);
            
            // Verify using commitments
            element_t expected_F, expected_G, expected_G_prime;
            element_init_G2(expected_F, params.pairing);
            element_init_G2(expected_G, params.pairing);
            element_init_G1(expected_G_prime, params.pairing);
            
            element_t power;
            element_init_Zr(power, params.pairing);
            element_set1(expected_F);
            element_set1(expected_G);
            element_set1(expected_G_prime);
            
            for (int j = 0; j < t; j++) {
                element_set_si(power, 1);
                for (int k = 0; k < j; k++) {
                    element_mul_si(power, power, i+1);
                }
                
                element_t temp;
                element_init_G2(temp, params.pairing);
                element_pow_zn(temp, Vx[l][j], power);
                element_mul(expected_F, expected_F, temp);
                
                element_pow_zn(temp, Vy[l][j], power);
                element_mul(expected_G, expected_G, temp);
                
                element_init_G1(temp, params.pairing);
                element_pow_zn(temp, Vy_prime[l][j], power);
                element_mul(expected_G_prime, expected_G_prime, temp);
                
                element_clear(temp);
            }
            
            // If verification fails, mark as disqualified
            element_t test_F, test_G, test_G_prime;
            element_init_G2(test_F, params.pairing);
            element_init_G2(test_G, params.pairing);
            element_init_G1(test_G_prime, params.pairing);
            
            element_pow_zn(test_F, params.g2, Fi);
            element_pow_zn(test_G, params.g2, Gi);
            element_pow_zn(test_G_prime, params.g1, Gi);
            
            if (!element_cmp(test_F, expected_F) || 
                !element_cmp(test_G, expected_G) || 
                !element_cmp(test_G_prime, expected_G_prime)) {
                disqualified[l] = true;
            }
            
            // Cleanup
            element_clear(Fi);
            element_clear(Gi);
            element_clear(expected_F);
            element_clear(expected_G);
            element_clear(expected_G_prime);
            element_clear(test_F);
            element_clear(test_G);
            element_clear(test_G_prime);
            element_clear(power);
        }
    }
    
    // Rest of your existing code for computing mvk and EA keys,
    // but only use non-disqualified authorities...
    // ... (previous implementation) ...
    
    // Cleanup
    for (int i = 0; i < ne; i++) {
        for (int j = 0; j < t; j++) {
            element_clear(F_coeffs[i][j]);
            element_clear(G_coeffs[i][j]);
            element_clear(Vx[i][j]);
            element_clear(Vy[i][j]);
            element_clear(Vy_prime[i][j]);
        }
    }
    
    return output;
}
