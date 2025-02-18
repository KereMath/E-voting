#include "keygen.h"
#include <pbc/pbc.h>
#include <gmp.h>
#include <vector>
#include <iostream>

// keygen fonksiyonunda kullanılacak yardımcı: polinom değerlendirmesi (Horner yöntemi)
static void evaluatePoly(const std::vector<element_t> &coeff, int m, const TIACParams &params, element_t result) {
    // m'yi Zr elemanı olarak ayarla.
    element_t m_val;
    element_init_Zr(m_val, params.pairing);
    element_set_si(m_val, m);

    // result = coeff[0]
    element_set(result, coeff[0]);
    // Horner yöntemi: for i=1 to t-1: result = result * m_val + coeff[i]
    for (size_t i = 1; i < coeff.size(); i++) {
        element_mul(result, result, m_val);
        element_add(result, result, coeff[i]);
    }
    element_clear(m_val);
}

KeyGenOutput keygen(const TIACParams &params, int t, int ne) {
    KeyGenOutput output;
    
    // 1. Zr'de t adet (t-1 derece) polinom katsayısı seç: v(z) ve w(z)
    std::vector<element_t> v_coeff(t), w_coeff(t);
    for (int i = 0; i < t; i++) {
        element_init_Zr(v_coeff[i], params.pairing);
        element_random(v_coeff[i]);
        element_init_Zr(w_coeff[i], params.pairing);
        element_random(w_coeff[i]);
    }
    
    // 2. Master gizli anahtar: v(0)=v_coeff[0], w(0)=w_coeff[0]
    element_t x_master, y_master;
    element_init_Zr(x_master, params.pairing);
    element_init_Zr(y_master, params.pairing);
    element_set(x_master, v_coeff[0]);
    element_set(y_master, w_coeff[0]);
    
    // 3. Master doğrulama anahtarı: mvk = (g1^(x_master^2), g1^(y_master^2), g1^(y_master))
    element_t exp;
    element_init_Zr(exp, params.pairing);
    
    // mvk.alpha2 = g1^(x_master^2)
    element_mul(exp, x_master, x_master);
    element_init_G1(output.mvk.alpha2, params.pairing);
    element_pow_zn(output.mvk.alpha2, params.g1, exp);
    
    // mvk.beta2 = g1^(y_master^2)
    element_mul(exp, y_master, y_master);
    element_init_G1(output.mvk.beta2, params.pairing);
    element_pow_zn(output.mvk.beta2, params.g1, exp);
    
    // mvk.beta1 = g1^(y_master)
    element_init_G1(output.mvk.beta1, params.pairing);
    element_pow_zn(output.mvk.beta1, params.g1, y_master);
    
    element_clear(exp);
    element_clear(x_master);
    element_clear(y_master);
    
    // 4. Her EA otoritesi için (m = 1 ... ne) anahtar üretimi:
    output.eaKeys.resize(ne);
    for (int m = 1; m <= ne; m++) {
        EAKey ea;
        // Gizli anahtar payı: sgkm = (v(m), w(m))
        element_init_Zr(ea.sgk_x, params.pairing);
        element_init_Zr(ea.sgk_y, params.pairing);
        evaluatePoly(v_coeff, m, params, ea.sgk_x);
        evaluatePoly(w_coeff, m, params, ea.sgk_y);
        
        // Public anahtar bileşenleri (vkm):
        // alpha2 = g1^(v(m)^2), beta2 = g1^(w(m)^2), beta1 = g1^(w(m))
        element_init_G1(ea.alpha2, params.pairing);
        element_init_G1(ea.beta2, params.pairing);
        element_init_G1(ea.beta1, params.pairing);
        
        element_t exp_val;
        element_init_Zr(exp_val, params.pairing);
        
        // alpha2 = g1^(v(m)^2)
        element_mul(exp_val, ea.sgk_x, ea.sgk_x);
        element_pow_zn(ea.alpha2, params.g1, exp_val);
        
        // beta2 = g1^(w(m)^2)
        element_mul(exp_val, ea.sgk_y, ea.sgk_y);
        element_pow_zn(ea.beta2, params.g1, exp_val);
        
        // beta1 = g1^(w(m))
        element_pow_zn(ea.beta1, params.g1, ea.sgk_y);
        
        element_clear(exp_val);
        
        output.eaKeys[m - 1] = ea;
    }
    
    // 5. Temizlik: Polinom katsayılarını serbest bırakın.
    for (int i = 0; i < t; i++) {
        element_clear(v_coeff[i]);
        element_clear(w_coeff[i]);
    }
    
    return output;
}
