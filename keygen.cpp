#include "keygen.h"
#include <iostream>

/**
 *  Basit bir sarmalayıcı struct: PBC element_t içerir.
 *  STL ile kopyalamada sorun yaşanmaması için,
 *  kopyalama vs. kapatılmıştır. (move da kapalı basitlik adına)
 */
struct ElemWrap {
    element_t val;

    // Default ctor: henüz init yok, init'i harici yapın.
    ElemWrap() {
        // Boş
    }

    // Yok edici: element_clear
    ~ElemWrap() {
        // init edilmeden clear çağrılırsa PBC hata verebilir.
        // O yüzden init edildiğini varsayıyoruz:
        // (Pratikte "initialized" bayrağı vs. kontrol edilebilir.)
        element_clear(val);
    }

    // Kopyalama engelli
    ElemWrap(const ElemWrap&) = delete;
    ElemWrap& operator=(const ElemWrap&) = delete;
};

/**
 * Polinom değerlendirme:
 * result = ∑ ( coeffs[k].val * X^k ),  k=0..coeffs.size()-1
 * (Zr alanında)
 */
static void evaluatePoly(const std::vector<ElemWrap> &coeffs,
                         int X,
                         TIACParams &params,
                         element_t result)
{
    element_set0(result); 

    element_t xVal;
    element_init_Zr(xVal, params.pairing);
    element_set_si(xVal, X);

    element_t power;
    element_init_Zr(power, params.pairing);
    element_set1(power);

    element_t tmp;
    element_init_Zr(tmp, params.pairing);

    for (size_t i = 0; i < coeffs.size(); i++) {
        element_mul(tmp, coeffs[i].val, power);
        element_add(result, result, tmp);
        element_mul(power, power, xVal);
    }

    element_clear(xVal);
    element_clear(power);
    element_clear(tmp);
}

/**
 * Pedersen’s DKG (şikayetsiz model).
 * Her EA polinom katsayılarını oluşturur, commitment hesaplar,
 * pay doğrular, mvk/msgk hesaplar, local payları döndürür.
 */
KeyGenOutput keygen(TIACParams &params, int t, int n)
{
    KeyGenOutput out;
    out.eaKeys.resize(n);

    // Polinom katsayılarını ElemWrap (element_t val) olarak tutacağız.
    // F_coeffs[i] => i. EA'nın F_i(X) katsayıları (t+1 adet)
    std::vector< std::vector<ElemWrap> > F_coeffs(n), G_coeffs(n);

    // 1) Rastgele katsayı seç, commit
    for(int i=0; i<n; i++){
        F_coeffs[i].resize(t+1);
        G_coeffs[i].resize(t+1);

        out.eaKeys[i].Vx.resize(t+1);
        out.eaKeys[i].Vy.resize(t+1);
        out.eaKeys[i].Vyprime.resize(t+1);

        for(int j=0; j<=t; j++){
            // init polinom katsayıları
            element_init_Zr(F_coeffs[i][j].val, params.pairing);
            element_random(F_coeffs[i][j].val);

            element_init_Zr(G_coeffs[i][j].val, params.pairing);
            element_random(G_coeffs[i][j].val);

            // init commitments
            element_init_G2(out.eaKeys[i].Vx[j], params.pairing);
            element_init_G2(out.eaKeys[i].Vy[j], params.pairing);
            element_init_G1(out.eaKeys[i].Vyprime[j], params.pairing);

            // Vx_{i,j} = g2^( x_{i,j} )
            element_pow_zn(out.eaKeys[i].Vx[j], params.g2, F_coeffs[i][j].val);
            // Vy_{i,j} = g2^( y_{i,j} )
            element_pow_zn(out.eaKeys[i].Vy[j], params.g2, G_coeffs[i][j].val);
            // Vy'_{i,j} = g1^( y_{i,j} )
            element_pow_zn(out.eaKeys[i].Vyprime[j], params.g1, G_coeffs[i][j].val);
        }
    }

    // 2) Sabit katsayılar x0, y0
    for(int i=0; i<n; i++){
        element_init_Zr(out.eaKeys[i].x0, params.pairing);
        element_init_Zr(out.eaKeys[i].y0, params.pairing);
        element_set(out.eaKeys[i].x0, F_coeffs[i][0].val);
        element_set(out.eaKeys[i].y0, G_coeffs[i][0].val);
    }

    // 3) Pay doğrulama (basitleştirilmiş, kimse şikayet etmiyor):
    {
        element_t fVal, gVal;
        element_init_Zr(fVal, params.pairing);
        element_init_Zr(gVal, params.pairing);

        element_t lhs_g2, rhs_g2;
        element_init_G2(lhs_g2, params.pairing);
        element_init_G2(rhs_g2, params.pairing);

        element_t lhs_g1, rhs_g1;
        element_init_G1(lhs_g1, params.pairing);
        element_init_G1(rhs_g1, params.pairing);

        element_t powL;
        element_init_Zr(powL, params.pairing);

        for(int i=0; i<n; i++){
            for(int L=1; L<=n; L++){
                evaluatePoly(F_coeffs[i], L, params, fVal);
                evaluatePoly(G_coeffs[i], L, params, gVal);

                // g2^(F_i(L)) ?= ∏ Vx[i][j]^(L^j)
                element_pow_zn(lhs_g2, params.g2, fVal);
                element_set1(rhs_g2);
                element_set1(powL);

                for(int j=0; j<=t; j++){
                    if(j>0) element_mul_si(powL, powL, L);
                    element_t tmpG2;
                    element_init_G2(tmpG2, params.pairing);
                    element_pow_zn(tmpG2, out.eaKeys[i].Vx[j], powL);
                    element_mul(rhs_g2, rhs_g2, tmpG2);
                    element_clear(tmpG2);
                }
                if(element_cmp(lhs_g2, rhs_g2) != 0){
                    std::cerr << "[WARN] F_i("<<L<<") tutarsız => i="<< i <<"\n";
                }

                // g2^(G_i(L)) ?= ∏ Vy[i][j]^(L^j)
                element_pow_zn(lhs_g2, params.g2, gVal);
                element_set1(rhs_g2);
                element_set1(powL);

                for(int j=0; j<=t; j++){
                    if(j>0) element_mul_si(powL, powL, L);
                    element_t tmpG2;
                    element_init_G2(tmpG2, params.pairing);
                    element_pow_zn(tmpG2, out.eaKeys[i].Vy[j], powL);
                    element_mul(rhs_g2, rhs_g2, tmpG2);
                    element_clear(tmpG2);
                }
                if(element_cmp(lhs_g2, rhs_g2) != 0){
                    std::cerr << "[WARN] G_i("<<L<<") tutarsız G2 => i="<< i <<"\n";
                }

                // g1^(G_i(L)) ?= ∏ Vyprime[i][j]^(L^j)
                element_pow_zn(lhs_g1, params.g1, gVal);
                element_set1(rhs_g1);
                element_set1(powL);

                for(int j=0; j<=t; j++){
                    if(j>0) element_mul_si(powL, powL, L);
                    element_t tmpG1;
                    element_init_G1(tmpG1, params.pairing);
                    element_pow_zn(tmpG1, out.eaKeys[i].Vyprime[j], powL);
                    element_mul(rhs_g1, rhs_g1, tmpG1);
                    element_clear(tmpG1);
                }
                if(element_cmp(lhs_g1, rhs_g1) != 0){
                    std::cerr << "[WARN] G_i("<<L<<") tutarsız G1 => i="<< i <<"\n";
                }
            }
        }

        element_clear(fVal);
        element_clear(gVal);
        element_clear(lhs_g2);
        element_clear(rhs_g2);
        element_clear(lhs_g1);
        element_clear(rhs_g1);
        element_clear(powL);
    }

    // 4) Master Verification Key (mvk) = (∏ Vx[i,0], ∏ Vy[i,0], ∏ Vy'[i,0])
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

    // 5) Master Signing Key (msgk) = (∑ x_{i0}, ∑ y_{i0})
    element_init_Zr(out.msgk.sk1, params.pairing);
    element_init_Zr(out.msgk.sk2, params.pairing);
    element_set0(out.msgk.sk1);
    element_set0(out.msgk.sk2);

    for(int i=0; i<n; i++){
        element_add(out.msgk.sk1, out.msgk.sk1, F_coeffs[i][0].val);
        element_add(out.msgk.sk2, out.msgk.sk2, G_coeffs[i][0].val);
    }

    // 6) Her EA => local pay: sgk1 = ∑_{l} F_l(i+1), sgk2 = ∑_{l} G_l(i+1)
    //    vki = ( g2^sgk1, g2^sgk2, g1^sgk2 )
    for(int i=0; i<n; i++){
        element_init_Zr(out.eaKeys[i].sgk1, params.pairing);
        element_init_Zr(out.eaKeys[i].sgk2, params.pairing);
        element_set0(out.eaKeys[i].sgk1);
        element_set0(out.eaKeys[i].sgk2);

        element_t tmpF, tmpG;
        element_init_Zr(tmpF, params.pairing);
        element_init_Zr(tmpG, params.pairing);

        for(int l=0; l<n; l++){
            evaluatePoly(F_coeffs[l], i+1, params, tmpF);
            evaluatePoly(G_coeffs[l], i+1, params, tmpG);
            element_add(out.eaKeys[i].sgk1, out.eaKeys[i].sgk1, tmpF);
            element_add(out.eaKeys[i].sgk2, out.eaKeys[i].sgk2, tmpG);
        }

        element_clear(tmpF);
        element_clear(tmpG);

        element_init_G2(out.eaKeys[i].vki1, params.pairing);
        element_init_G2(out.eaKeys[i].vki2, params.pairing);
        element_init_G1(out.eaKeys[i].vki3, params.pairing);

        element_pow_zn(out.eaKeys[i].vki1, params.g2, out.eaKeys[i].sgk1);
        element_pow_zn(out.eaKeys[i].vki2, params.g2, out.eaKeys[i].sgk2);
        element_pow_zn(out.eaKeys[i].vki3, params.g1, out.eaKeys[i].sgk2);
    }

    // 7) ElemWrap otomatik yok ediciler devreye girince 
    //    element_clear(...) yapacak. Polinomun boyutu sabit kalabilir,
    //    extra bir adımda .clear() yaparsanız destructorlar devreye girer.

    // Ama eğer vector'ı .clear() ederseniz destructorlar çağrılacak.
    // out.eaKeys'leri vs. main'de finalde element_clear diyerek kapatın.

    return out;
}
