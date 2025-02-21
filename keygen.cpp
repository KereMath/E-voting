#include "keygen.h"
#include <pbc/pbc.h>
#include <gmp.h>
#include <vector>
#include <iostream>

// Helper function: Evaluate a polynomial at point X using Horner's method
static void evaluatePoly(std::vector<element_t>& coeff, int X, TIACParams& params, element_t result) {
    element_t X_val;
    element_init_Zr(X_val, params.pairing);
    element_set_si(X_val, X);
    
    element_set(result, coeff[0]); // Initialize with constant term
    for (size_t i = 1; i < coeff.size(); i++) {
        element_mul(result, result, X_val); // result = result * X
        element_add(result, result, coeff[i]); // result = result + coeff[i]
    }
    element_clear(X_val);
}

// Main key generation function
KeyGenOutput keygen(TIACParams params, int t, int ne) {
    KeyGenOutput output;
    
    // Initialize MasterVK elements
    element_init_G2(output.mvk.alpha2, params.pairing);
    element_init_G2(output.mvk.beta2, params.pairing);
    element_init_G1(output.mvk.beta1, params.pairing);

    // Resize eaKeys and initialize its elements
    output.eaKeys.resize(ne);
    for (int i = 0; i < ne; i++) {
        element_init_Zr(output.eaKeys[i].sgk1, params.pairing);
        element_init_Zr(output.eaKeys[i].sgk2, params.pairing);
        element_init_G2(output.eaKeys[i].vkm1, params.pairing);
        element_init_G2(output.eaKeys[i].vkm2, params.pairing);
        element_init_G1(output.eaKeys[i].vkm3, params.pairing);
    }

    // 1. Generate polynomials (degree t-1, so t coefficients)
    std::vector<std::vector<element_t>> F_coeffs(ne), G_coeffs(ne);
    for (int i = 0; i < ne; i++) {
        F_coeffs[i].resize(t);
        G_coeffs[i].resize(t);
        for (int j = 0; j < t; j++) {
            element_init_Zr(F_coeffs[i][j], params.pairing);
            element_random(F_coeffs[i][j]);
            element_init_Zr(G_coeffs[i][j], params.pairing);
            element_random(G_coeffs[i][j]);
        }
    }

    // 2. Compute master secret (sum of constant terms)
    element_t sk1, sk2;
    element_init_Zr(sk1, params.pairing);
    element_init_Zr(sk2, params.pairing);
    element_set0(sk1);
    element_set0(sk2);
    for (int i = 0; i < ne; i++) {
        element_add(sk1, sk1, F_coeffs[i][0]); // ∑ xi0
        element_add(sk2, sk2, G_coeffs[i][0]); // ∑ yi0
    }

    // 3. Compute master verification key (mvk)
    element_pow_zn(output.mvk.alpha2, params.g2, sk1); // g2^(∑ xi0)
    element_pow_zn(output.mvk.beta2, params.g2, sk2);  // g2^(∑ yi0)
    element_pow_zn(output.mvk.beta1, params.g1, sk2);  // g1^(∑ yi0)

    // 4. Compute EA shares
    for (int i = 1; i <= ne; i++) {
        element_t sgk1, sgk2;
        element_init_Zr(sgk1, params.pairing);
        element_init_Zr(sgk2, params.pairing);
        element_set0(sgk1);
        element_set0(sgk2);

        for (int l = 0; l < ne; l++) {
            element_t valF, valG;
            element_init_Zr(valF, params.pairing);
            element_init_Zr(valG, params.pairing);
            evaluatePoly(F_coeffs[l], i, params, valF); // Fl(i)
            evaluatePoly(G_coeffs[l], i, params, valG); // Gl(i)
            element_add(sgk1, sgk1, valF); // ∑ Fl(i)
            element_add(sgk2, sgk2, valG); // ∑ Gl(i)
            element_clear(valF);
            element_clear(valG);
        }

        // Set signing key shares
        element_set(output.eaKeys[i-1].sgk1, sgk1);
        element_set(output.eaKeys[i-1].sgk2, sgk2);

        // Compute verification key components
        element_pow_zn(output.eaKeys[i-1].vkm1, params.g2, sgk1); // g2^F(i)
        element_pow_zn(output.eaKeys[i-1].vkm2, params.g2, sgk2); // g2^G(i)
        element_pow_zn(output.eaKeys[i-1].vkm3, params.g1, sgk2); // g1^G(i)

        element_clear(sgk1);
        element_clear(sgk2);
    }

    // 5. Cleanup temporary variables
    for (int i = 0; i < ne; i++) {
        for (int j = 0; j < t; j++) {
            element_clear(F_coeffs[i][j]);
            element_clear(G_coeffs[i][j]);
        }
    }
    element_clear(sk1);
    element_clear(sk2);

    return output;
}

// Cleanup function for KeyGenOutput
void clearKeyGenOutput(KeyGenOutput& output) {
    element_clear(output.mvk.alpha2);
    element_clear(output.mvk.beta2);
    element_clear(output.mvk.beta1);
    for (auto& key : output.eaKeys) {
        element_clear(key.sgk1);
        element_clear(key.sgk2);
        element_clear(key.vkm1);
        element_clear(key.vkm2);
        element_clear(key.vkm3);
    }
}