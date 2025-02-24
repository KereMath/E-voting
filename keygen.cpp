#include "keygen.h"
#include <pbc/pbc.h>
#include <gmp.h>
#include <vector>
#include <iostream>

// Updated: remove const so coeff[0] yields a non-const element.
static void evaluatePoly(std::vector<element_t>& coeff, int X, TIACParams &params, element_t result) {
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
    
    // 1. Initialize F and G polynomial coefficients as 2D vectors of element_t.
    std::vector< std::vector<element_t> > F_coeffs(ne, std::vector<element_t>(t));
    std::vector< std::vector<element_t> > G_coeffs(ne, std::vector<element_t>(t));
    for (int i = 0; i < ne; i++) {
        for (int j = 0; j < t; j++) {
            // Initialize each coefficient in Zr.
            element_init_Zr(F_coeffs[i][j], params.pairing);
            element_random(F_coeffs[i][j]);
            
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
        
        output.eaKeys[i - 1] = ea;
    }
    
    // Pseudocode for storing commitments (for each EA i):
    std::vector<std::vector<element_t>> Vxij(ne, std::vector<element_t>(t));
    std::vector<std::vector<element_t>> Vyij(ne, std::vector<element_t>(t));
    std::vector<std::vector<element_t>> Vyij_prime(ne, std::vector<element_t>(t));
    for (int i = 0; i < ne; i++) {
        for (int j = 0; j < t; j++) {
            element_init_G2(Vxij[i][j], params.pairing);
            element_pow_zn(Vxij[i][j], params.g2, F_coeffs[i][j]);
            
            element_init_G2(Vyij[i][j], params.pairing);
            element_pow_zn(Vyij[i][j], params.g2, G_coeffs[i][j]);
            
            element_init_G1(Vyij_prime[i][j], params.pairing);
            element_pow_zn(Vyij_prime[i][j], params.g1, G_coeffs[i][j]);
            
            // Distribute Vxij, Vyij, Vyij_prime to other EAs
        }
    }
    
    // Verification using commitments
    std::vector<bool> complaints(ne, false);
    for (int i = 1; i <= ne; i++) {
        for (int l = 0; l < ne; l++) {
            element_t lhs, rhs, temp, exp;
            element_init_G2(lhs, params.pairing);
            element_init_G2(rhs, params.pairing);
            element_set1(lhs);
            element_set1(rhs);
            
            for (int j = 0; j < t; j++) {
                element_init_Zr(exp, params.pairing);
                element_set_si(exp, i * j);
                
                element_init_G2(temp, params.pairing);
                element_pow_zn(temp, Vxij[l][j], exp);
                element_mul(lhs, lhs, temp);
                element_clear(temp);
                
                element_init_G2(temp, params.pairing);
                element_pow_zn(temp, Vyij[l][j], exp);
                element_mul(rhs, rhs, temp);
                element_clear(temp);
                
                element_clear(exp);
            }
            
            element_t Fl_i, Gl_i, g2_Fl_i, g2_Gl_i;
            element_init_Zr(Fl_i, params.pairing);
            element_init_Zr(Gl_i, params.pairing);
            evaluatePoly(F_coeffs[l], i, params, Fl_i);
            evaluatePoly(G_coeffs[l], i, params, Gl_i);
            
            element_init_G2(g2_Fl_i, params.pairing);
            element_init_G2(g2_Gl_i, params.pairing);
            element_pow_zn(g2_Fl_i, params.g2, Fl_i);
            element_pow_zn(g2_Gl_i, params.g2, Gl_i);
            
            if (!element_cmp(lhs, g2_Fl_i) || !element_cmp(rhs, g2_Gl_i)) {
                complaints[l] = true;
            }
            
            element_clear(lhs);
            element_clear(rhs);
            element_clear(Fl_i);
            element_clear(Gl_i);
            element_clear(g2_Fl_i);
            element_clear(g2_Gl_i);
        }
    }
    
    // Complaint handling and forming subset Q
    std::vector<int> Q;
    for (int i = 0; i < ne; i++) {
        if (!complaints[i]) {
            Q.push_back(i);
        }
    }
    
    // Use only authorities in Q to aggregate final sgk, mvk
    element_t final_sgk1, final_sgk2;
    element_init_Zr(final_sgk1, params.pairing);
    element_init_Zr(final_sgk2, params.pairing);
    element_set1(final_sgk1);
    element_set1(final_sgk2);
    
    for (int i : Q) {
        element_mul(final_sgk1, final_sgk1, F_coeffs[i][0]);
        element_mul(final_sgk2, final_sgk2, G_coeffs[i][0]);
    }
    
    element_init_G1(output.mvk.alpha2, params.pairing);
    element_pow_zn(output.mvk.alpha2, params.g1, final_sgk1);
    
    element_init_G1(output.mvk.beta2, params.pairing);
    element_pow_zn(output.mvk.beta2, params.g1, final_sgk2);
    
    element_clear(final_sgk1);
    element_clear(final_sgk2);
    
    // 5. Polinom katsayılarını serbest bırakma
    for (int i = 0; i < ne; i++) {
        for (int j = 0; j < t; j++) {
            element_clear(F_coeffs[i][j]);
            element_clear(G_coeffs[i][j]);
        }
    }
    
    return output;
}
