#include <iostream>
#include <pbc/pbc.h>
#include <gmp.h>
#include <cstring>

/**
 *  Küçük boyutlu “type a” parametresi, PBC’nin örnek param dosyalarından esinlenilmiştir.
 *  Aslında 159-bit gibi daha küçük bir eğri. Fakat “pedersen dkg” testimizde mismatch olmadan çalışır.
 */
static const char* TYPE_A_PARAM = R"(
type a
q 878071079966331252243778198475404981580688919448
h 1201601226489114607938882136674053420480295440125131182296
r 730750818665451621361119245571504901405976559617
exp2 159
exp1 107
sign1 1
sign0 1
)";

//----------------------------------
// Basit yapımız: 2 otorite (n=2), t=1
// Polinom derecesi = 1 => F_i(X)= x_{i0} + x_{i1}X
//----------------------------------

struct TIACParams {
    pairing_t pairing;
    mpz_t prime_order;
    element_t g1;
    element_t g2;
};

struct EAKey {
    // Sabit terimler (x0,y0)
    element_t x0; 
    element_t y0;

    // t+1=2 commitment => Vx[0],Vx[1]; Vy[0],Vy[1]; Vy'[0],Vy'[1]
    element_t Vx[2];
    element_t Vy[2];
    element_t Vyprime[2];

    // local share
    element_t sgk1; // ∑ F_l(i)
    element_t sgk2; // ∑ G_l(i)
    element_t vki1; // g2^(sgk1)
    element_t vki2; // g2^(sgk2)
    element_t vki3; // g1^(sgk2)
};

struct MasterVK {
    element_t vk1;
    element_t vk2;
    element_t vk3;
};

struct MasterSK {
    element_t sk1;
    element_t sk2;
};

struct KeyGenOutput {
    MasterVK mvk;
    MasterSK msgk;
    EAKey eaKeys[2]; // n=2 sabit
};

//----------------------------------
// Setup: param type a
//----------------------------------
TIACParams setupParams() {
    TIACParams P;
    pbc_param_t pp;
    pbc_param_init_set_buf(pp, TYPE_A_PARAM, std::strlen(TYPE_A_PARAM));
    pairing_init_pbc_param(P.pairing, pp);
    pbc_param_clear(pp);

    mpz_init_set(P.prime_order, P.pairing->r);

    element_init_G1(P.g1, P.pairing);
    element_init_G2(P.g2, P.pairing);

    // Rastgele
    element_random(P.g1);
    element_random(P.g2);

    // e(g1,g2) != 1
    element_t tmpGT;
    element_init_GT(tmpGT, P.pairing);
    pairing_apply(tmpGT, P.g1, P.g2, P.pairing);
    int tries=0;
    while(element_is1(tmpGT) && tries<16){
        element_random(P.g1);
        element_random(P.g2);
        pairing_apply(tmpGT, P.g1, P.g2, P.pairing);
        tries++;
    }
    element_clear(tmpGT);

    return P;
}

//----------------------------------
// Evaluate degree=1 poly:
// polynom = { c0, c1 }
// F(l) = c0 + c1*l  (mod r)
//----------------------------------
void evaluatePoly(element_t c0, element_t c1, int l, pairing_t pairing, element_t outVal){
    // outVal = c0 + c1*l (mod r)
    element_t tmp;
    element_init_Zr(tmp, pairing);
    element_t lVal;
    element_init_Zr(lVal, pairing);

    element_set_si(lVal, l);  // l

    // c1*lVal
    element_mul(tmp, c1, lVal);

    // outVal= c0 + tmp
    element_add(outVal, c0, tmp);

    element_clear(tmp);
    element_clear(lVal);
}

//----------------------------------
// n=2, t=1, each EA_i => polynom F_i, G_i
// F_i(X)= x_{i0} + x_{i1}*X, G_i(X)= y_{i0}+y_{i1}*X
//----------------------------------
KeyGenOutput keygen(TIACParams &P){
    KeyGenOutput out;

    // Polinom katsayilari: x_{i0}, x_{i1}, y_{i0}, y_{i1}
    // i=0..1 (toplam 2 EA)
    // Her polinom (F_i) => x_{i0}+ x_{i1}*X  => 2 katsayi
    // Rastgele secelim
    element_t x[2][2], y[2][2]; // x[i][0], x[i][1], y[i][0], y[i][1]
    for(int i=0; i<2; i++){
        for(int j=0; j<2; j++){
            element_init_Zr(x[i][j], P.pairing);
            element_init_Zr(y[i][j], P.pairing);
            element_random(x[i][j]);
            element_random(y[i][j]);
        }
    }

    // t+1=2 => commitments:
    // Vx[i][0] = g2^x_{i0}, Vx[i][1] = g2^x_{i1}, ...
    for(int i=0; i<2; i++){
        // EAKey sabit terimler
        element_init_Zr(out.eaKeys[i].x0, P.pairing);
        element_set(out.eaKeys[i].x0, x[i][0]);

        element_init_Zr(out.eaKeys[i].y0, P.pairing);
        element_set(out.eaKeys[i].y0, y[i][0]);

        // commitments
        for(int j=0; j<2; j++){
            element_init_G2(out.eaKeys[i].Vx[j], P.pairing);
            element_pow_zn(out.eaKeys[i].Vx[j], P.g2, x[i][j]);

            element_init_G2(out.eaKeys[i].Vy[j], P.pairing);
            element_pow_zn(out.eaKeys[i].Vy[j], P.g2, y[i][j]);

            element_init_G1(out.eaKeys[i].Vyprime[j], P.pairing);
            element_pow_zn(out.eaKeys[i].Vyprime[j], P.g1, y[i][j]);
        }
    }

    // Pay dogrulama => for i in [0..1], for l in [1..2]:
    // F_i(l) = x_{i0}+x_{i1}*l
    // Check: g2^F_i(l) = Vx[i][0]^ (l^0) * Vx[i][1]^ (l^1)
    {
        element_t fVal, gVal, lhsG2, rhsG2, lhsG1, rhsG1;
        element_init_Zr(fVal, P.pairing);
        element_init_Zr(gVal, P.pairing);
        element_init_G2(lhsG2, P.pairing);
        element_init_G2(rhsG2, P.pairing);
        element_init_G1(lhsG1, P.pairing);
        element_init_G1(rhsG1, P.pairing);

        for(int i=0; i<2; i++){
            for(int l=1; l<=2; l++){
                // F_i(l)
                evaluatePoly(x[i][0], x[i][1], l, P.pairing, fVal);
                // G_i(l)
                evaluatePoly(y[i][0], y[i][1], l, P.pairing, gVal);

                // Check 1: g2^fVal ?= product_{j=0..1} Vx[i][j]^( l^j )
                // l^0=1, l^1=l
                element_pow_zn(lhsG2, P.g2, fVal);

                element_set1(rhsG2);
                // j=0
                element_mul(rhsG2, rhsG2, out.eaKeys[i].Vx[0]); // l^0=1 => Vx[i][0]^1
                // j=1 => exponent l
                element_t eExp;
                element_init_Zr(eExp, P.pairing);
                element_set_si(eExp, l);
                element_t tmpG2;
                element_init_G2(tmpG2, P.pairing);
                element_pow_zn(tmpG2, out.eaKeys[i].Vx[1], eExp);
                element_mul(rhsG2, rhsG2, tmpG2);
                element_clear(tmpG2);
                element_clear(eExp);

                if(element_cmp(lhsG2, rhsG2)!=0){
                    std::cerr<<"[MISMATCH] F_i("<<l<<") => i="<<i<<"\n";
                }

                // Check 2: g2^gVal ?= Vy[i][0]^(1) * Vy[i][1]^(l)
                element_pow_zn(lhsG2, P.g2, gVal);
                element_set1(rhsG2);
                element_mul(rhsG2, rhsG2, out.eaKeys[i].Vy[0]); // l^0=1
                {
                    element_t eExp2;
                    element_init_Zr(eExp2, P.pairing);
                    element_set_si(eExp2, l);
                    element_t tmp2;
                    element_init_G2(tmp2, P.pairing);
                    element_pow_zn(tmp2, out.eaKeys[i].Vy[1], eExp2);
                    element_mul(rhsG2, rhsG2, tmp2);
                    element_clear(tmp2);
                    element_clear(eExp2);
                }
                if(element_cmp(lhsG2, rhsG2)!=0){
                    std::cerr<<"[MISMATCH] G_i("<<l<<") => i="<<i<<" in G2\n";
                }

                // Check 3: g1^gVal ?= Vyprime[i][0]^1 * Vyprime[i][1]^l
                element_pow_zn(lhsG1, P.g1, gVal);
                element_set1(rhsG1);
                element_mul(rhsG1, rhsG1, out.eaKeys[i].Vyprime[0]);
                {
                    element_t eExp2;
                    element_init_Zr(eExp2, P.pairing);
                    element_set_si(eExp2, l);
                    element_t tmpG1;
                    element_init_G1(tmpG1, P.pairing);
                    element_pow_zn(tmpG1, out.eaKeys[i].Vyprime[1], eExp2);
                    element_mul(rhsG1, rhsG1, tmpG1);
                    element_clear(tmpG1);
                    element_clear(eExp2);
                }
                if(element_cmp(lhsG1, rhsG1)!=0){
                    std::cerr<<"[MISMATCH] G_i("<<l<<") => i="<<i<<" in G1\n";
                }
            }
        }

        element_clear(fVal);
        element_clear(gVal);
        element_clear(lhsG2);
        element_clear(rhsG2);
        element_clear(lhsG1);
        element_clear(rhsG1);
    }

    // Master VK = ∏( Vx[i][0] ), ∏(Vy[i][0]), ∏(Vyprime[i][0]) ; i=0..1
    element_init_G2(out.mvk.vk1, P.pairing);
    element_init_G2(out.mvk.vk2, P.pairing);
    element_init_G1(out.mvk.vk3, P.pairing);
    element_set1(out.mvk.vk1);
    element_set1(out.mvk.vk2);
    element_set1(out.mvk.vk3);

    for(int i=0; i<2; i++){
        element_mul(out.mvk.vk1, out.mvk.vk1, out.eaKeys[i].Vx[0]);
        element_mul(out.mvk.vk2, out.mvk.vk2, out.eaKeys[i].Vy[0]);
        element_mul(out.mvk.vk3, out.mvk.vk3, out.eaKeys[i].Vyprime[0]);
    }

    // Master SK= ∑ x_{i0}, ∑ y_{i0}
    element_init_Zr(out.msgk.sk1, P.pairing);
    element_init_Zr(out.msgk.sk2, P.pairing);
    element_set0(out.msgk.sk1);
    element_set0(out.msgk.sk2);

    for(int i=0; i<2; i++){
        element_add(out.msgk.sk1, out.msgk.sk1, x[i][0]);
        element_add(out.msgk.sk2, out.msgk.sk2, y[i][0]);
    }

    // local share: sgk1= ∑_{l=0..1} F_l(i+1), i=0..1
    //   polinom l => x[l][0],x[l][1]
    //   evaluatePoly(x[l][0], x[l][1], i+1)
    for(int i=0; i<2; i++){
        element_init_Zr(out.eaKeys[i].sgk1, P.pairing);
        element_init_Zr(out.eaKeys[i].sgk2, P.pairing);
        element_set0(out.eaKeys[i].sgk1);
        element_set0(out.eaKeys[i].sgk2);

        for(int l=0; l<2; l++){
            element_t valF, valG;
            element_init_Zr(valF, P.pairing);
            element_init_Zr(valG, P.pairing);

            evaluatePoly(x[l][0], x[l][1], i+1, P.pairing, valF);
            evaluatePoly(y[l][0], y[l][1], i+1, P.pairing, valG);

            element_add(out.eaKeys[i].sgk1, out.eaKeys[i].sgk1, valF);
            element_add(out.eaKeys[i].sgk2, out.eaKeys[i].sgk2, valG);
            element_clear(valF);
            element_clear(valG);
        }

        element_init_G2(out.eaKeys[i].vki1, P.pairing);
        element_init_G2(out.eaKeys[i].vki2, P.pairing);
        element_init_G1(out.eaKeys[i].vki3, P.pairing);

        element_pow_zn(out.eaKeys[i].vki1, P.g2, out.eaKeys[i].sgk1);
        element_pow_zn(out.eaKeys[i].vki2, P.g2, out.eaKeys[i].sgk2);
        element_pow_zn(out.eaKeys[i].vki3, P.g1, out.eaKeys[i].sgk2);
    }

    // polinom bellek temizleyelim
    for(int i=0; i<2; i++){
        for(int j=0; j<2; j++){
            element_clear(x[i][j]);
            element_clear(y[i][j]);
        }
    }

    return out;
}


//----------------------------------
// main
//----------------------------------
int main(){
    // 1) Setup
    TIACParams P = setupParams();

    // 2) KeyGen (2 EA, t=1)
    KeyGenOutput out = keygen(P);

    std::cout<<"=== KeyGen bitti. Bak:\n";
    {
        char buf[512];
        element_snprintf(buf,sizeof(buf),"%B", out.mvk.vk1);
        std::cout<<"mvk.vk1= "<<buf<<"\n";
    }

    // Sonda bellek temizliği
    // Master VK
    element_clear(out.mvk.vk1);
    element_clear(out.mvk.vk2);
    element_clear(out.mvk.vk3);

    // Master SK
    element_clear(out.msgk.sk1);
    element_clear(out.msgk.sk2);

    // EAKey
    for(int i=0; i<2; i++){
        element_clear(out.eaKeys[i].x0);
        element_clear(out.eaKeys[i].y0);
        for(int j=0; j<2; j++){
            element_clear(out.eaKeys[i].Vx[j]);
            element_clear(out.eaKeys[i].Vy[j]);
            element_clear(out.eaKeys[i].Vyprime[j]);
        }
        element_clear(out.eaKeys[i].sgk1);
        element_clear(out.eaKeys[i].sgk2);
        element_clear(out.eaKeys[i].vki1);
        element_clear(out.eaKeys[i].vki2);
        element_clear(out.eaKeys[i].vki3);
    }

    // Setup param
    element_clear(P.g1);
    element_clear(P.g2);
    mpz_clear(P.prime_order);
    pairing_clear(P.pairing);

    std::cout<<"[INFO] Program sonu.\n";
    return 0;
}
