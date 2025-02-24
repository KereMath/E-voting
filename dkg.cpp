#include <iostream>
#include <pbc/pbc.h>
#include <gmp.h>
#include <cstring>

// -- BN-256 param (type f) --
static const char* BN256_PARAM = R"(
type f
q 186944716490498228592211144210229761989241675946164825413929
r 186944716490498228592211144210229761989241675946164825526319
b 1
beta 109341043287096796981443118641762728007143963588
alpha0 147354120310549301445722100263386112552812769040
alpha1 12707752274141484575335849047546472705710528192
)";

// ----------------- Setup Yapisi -----------------
struct TIACParams {
    pairing_t pairing;
    mpz_t prime_order;
    element_t g1;
    element_t g2;
};

TIACParams setupParams() {
    TIACParams p;
    pbc_param_t pbc;
    pbc_param_init_set_buf(pbc, BN256_PARAM, std::strlen(BN256_PARAM));
    pairing_init_pbc_param(p.pairing, pbc);
    pbc_param_clear(pbc);

    mpz_init_set(p.prime_order, p.pairing->r);

    element_init_G1(p.g1, p.pairing);
    element_init_G2(p.g2, p.pairing);

    element_random(p.g1);
    element_random(p.g2);

    // e(g1,g2) != 1 kontrolü
    element_t tmpGT;
    element_init_GT(tmpGT, p.pairing);
    pairing_apply(tmpGT, p.g1, p.g2, p.pairing);
    int tries = 0;
    while(element_is1(tmpGT) && tries<32) {
        element_random(p.g1);
        element_random(p.g2);
        pairing_apply(tmpGT, p.g1, p.g2, p.pairing);
        tries++;
    }
    element_clear(tmpGT);

    return p;
}

// --------------- EAKey / Output Yapilari -----------
struct EAKey {
    // sabit terimler
    element_t x0; 
    element_t y0;

    // t+1 commitments
    element_t *Vx;      // dizi => g2^( x_{ij} )
    element_t *Vy;      // dizi => g2^( y_{ij} )
    element_t *Vyprime; // dizi => g1^( y_{ij} )

    // local pay
    element_t sgk1;
    element_t sgk2;
    element_t vki1;
    element_t vki2;
    element_t vki3;
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
    EAKey* eaKeys; // dizi [n]
};

// --------------- Evaluate Polynom (mod r) ----------------
static void evaluatePoly(element_s *coeffs, // katsayilari [t+1]
                         int t,
                         int L,
                         TIACParams &params,
                         element_t outVal)
{
    // outVal = ∑_{k=0..t} coeffs[k] * L^k (mod r)
    element_set0(outVal);

    element_t xVal;
    element_init_Zr(xVal, params.pairing);
    element_set_si(xVal, L);  // L mod r

    element_t power;
    element_init_Zr(power, params.pairing);
    element_set1(power);

    element_t tmp;
    element_init_Zr(tmp, params.pairing);

    for(int k_i = 0; k_i <= t; k_i++){
        // tmp = coeffs[k_i]*power
        element_mul(tmp, &coeffs[k_i], power);
        element_add(outVal, outVal, tmp);
        element_mul(power, power, xVal);
    }

    element_clear(xVal);
    element_clear(power);
    element_clear(tmp);
}

// --------------- KeyGen (Pedersen's DKG) ----------------
KeyGenOutput keygen(TIACParams &params, int t, int n) {
    KeyGenOutput out;
    // EAKey dizisi
    out.eaKeys = new EAKey[n];

    // Polinom katsayilari F[i], G[i] => pointer dizisi
    element_s** F = new element_s*[n];
    element_s** G = new element_s*[n];

    // 1) Rastgele polinom olusturma
    for(int i=0; i<n; i++){
        F[i] = new element_s[t+1];
        G[i] = new element_s[t+1];
        for(int j=0; j<=t; j++){
            element_init_Zr(&F[i][j], params.pairing);
            element_random(&F[i][j]);
            element_init_Zr(&G[i][j], params.pairing);
            element_random(&G[i][j]);
        }
    }

    // 2) EAKey: commitments (t+1 dizisi)
    for(int i=0; i<n; i++){
        out.eaKeys[i].Vx      = new element_t[t+1];
        out.eaKeys[i].Vy      = new element_t[t+1];
        out.eaKeys[i].Vyprime = new element_t[t+1];

        // init + pow
        for(int j=0; j<=t; j++){
            element_init_G2(out.eaKeys[i].Vx[j], params.pairing);
            element_pow_zn(out.eaKeys[i].Vx[j], params.g2, &F[i][j]);

            element_init_G2(out.eaKeys[i].Vy[j], params.pairing);
            element_pow_zn(out.eaKeys[i].Vy[j], params.g2, &G[i][j]);

            element_init_G1(out.eaKeys[i].Vyprime[j], params.pairing);
            element_pow_zn(out.eaKeys[i].Vyprime[j], params.g1, &G[i][j]);
        }
    }

    // 3) sabit terimler x0,y0
    for(int i=0; i<n; i++){
        element_init_Zr(out.eaKeys[i].x0, params.pairing);
        element_set(out.eaKeys[i].x0, &F[i][0]);

        element_init_Zr(out.eaKeys[i].y0, params.pairing);
        element_set(out.eaKeys[i].y0, &G[i][0]);
    }

    // 4) Pay dogrulama
    element_t fVal, gVal;
    element_init_Zr(fVal, params.pairing);
    element_init_Zr(gVal, params.pairing);

    element_t lhsG2, rhsG2;
    element_init_G2(lhsG2, params.pairing);
    element_init_G2(rhsG2, params.pairing);

    element_t lhsG1, rhsG1;
    element_init_G1(lhsG1, params.pairing);
    element_init_G1(rhsG1, params.pairing);

    element_t eExp;
    element_init_Zr(eExp, params.pairing);

    for(int i=0; i<n; i++){
        for(int L=1; L<=n; L++){
            // F_i(L), G_i(L)
            evaluatePoly(F[i], t, L, params, fVal);
            evaluatePoly(G[i], t, L, params, gVal);

            // lhs = g2^F_i(L)
            element_pow_zn(lhsG2, params.g2, fVal);
            // rhs = ∏ [ Vx[i][j]^( L^j )]
            element_set1(rhsG2);
            long powInt=1;
            for(int j=0; j<=t; j++){
                if(j>0) powInt *= L; // normal int
                element_set_si(eExp, powInt); // eExp in Zr
                element_t tmpG2;
                element_init_G2(tmpG2, params.pairing);
                element_pow_zn(tmpG2, out.eaKeys[i].Vx[j], eExp);
                element_mul(rhsG2, rhsG2, tmpG2);
                element_clear(tmpG2);
            }
            if(element_cmp(lhsG2, rhsG2)!=0){
                std::cerr<<"[WARN] F_i("<<L<<") mismatch => i="<<i<<"\n";
            }

            // lhs = g2^G_i(L)
            element_pow_zn(lhsG2, params.g2, gVal);
            element_set1(rhsG2);
            powInt=1;
            for(int j=0; j<=t; j++){
                if(j>0) powInt *= L;
                element_set_si(eExp, powInt);
                element_t tmpG2;
                element_init_G2(tmpG2, params.pairing);
                element_pow_zn(tmpG2, out.eaKeys[i].Vy[j], eExp);
                element_mul(rhsG2, rhsG2, tmpG2);
                element_clear(tmpG2);
            }
            if(element_cmp(lhsG2, rhsG2)!=0){
                std::cerr<<"[WARN] G_i("<<L<<") mismatch G2 => i="<<i<<"\n";
            }

            // lhs = g1^G_i(L)
            element_pow_zn(lhsG1, params.g1, gVal);
            element_set1(rhsG1);
            powInt=1;
            for(int j=0; j<=t; j++){
                if(j>0) powInt *= L;
                element_set_si(eExp, powInt);
                element_t tmpG1;
                element_init_G1(tmpG1, params.pairing);
                element_pow_zn(tmpG1, out.eaKeys[i].Vyprime[j], eExp);
                element_mul(rhsG1, rhsG1, tmpG1);
                element_clear(tmpG1);
            }
            if(element_cmp(lhsG1, rhsG1)!=0){
                std::cerr<<"[WARN] G_i("<<L<<") mismatch G1 => i="<<i<<"\n";
            }
        }
    }

    element_clear(eExp);
    element_clear(fVal);
    element_clear(gVal);
    element_clear(lhsG2);
    element_clear(rhsG2);
    element_clear(lhsG1);
    element_clear(rhsG1);

    // 5) Master VK
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

    // 6) Master SK
    element_init_Zr(out.msgk.sk1, params.pairing);
    element_init_Zr(out.msgk.sk2, params.pairing);
    element_set0(out.msgk.sk1);
    element_set0(out.msgk.sk2);
    for(int i=0; i<n; i++){
        element_add(out.msgk.sk1, out.msgk.sk1, &F[i][0]);
        element_add(out.msgk.sk2, out.msgk.sk2, &G[i][0]);
    }

    // 7) local share
    for(int i=0; i<n; i++){
        element_init_Zr(out.eaKeys[i].sgk1, params.pairing);
        element_init_Zr(out.eaKeys[i].sgk2, params.pairing);
        element_set0(out.eaKeys[i].sgk1);
        element_set0(out.eaKeys[i].sgk2);

        for(int L=0; L<n; L++){
            element_t valF, valG;
            element_init_Zr(valF, params.pairing);
            element_init_Zr(valG, params.pairing);
            evaluatePoly(F[L], t, i+1, params, valF);
            evaluatePoly(G[L], t, i+1, params, valG);
            element_add(out.eaKeys[i].sgk1, out.eaKeys[i].sgk1, valF);
            element_add(out.eaKeys[i].sgk2, out.eaKeys[i].sgk2, valG);
            element_clear(valF);
            element_clear(valG);
        }
        element_init_G2(out.eaKeys[i].vki1, params.pairing);
        element_init_G2(out.eaKeys[i].vki2, params.pairing);
        element_init_G1(out.eaKeys[i].vki3, params.pairing);

        element_pow_zn(out.eaKeys[i].vki1, params.g2, out.eaKeys[i].sgk1);
        element_pow_zn(out.eaKeys[i].vki2, params.g2, out.eaKeys[i].sgk2);
        element_pow_zn(out.eaKeys[i].vki3, params.g1, out.eaKeys[i].sgk2);
    }

    // 8) Polinom bellek temizligi
    for(int i=0; i<n; i++){
        for(int j=0; j<=t; j++){
            element_clear(&F[i][j]);
            element_clear(&G[i][j]);
        }
        delete[] F[i];
        delete[] G[i];
    }
    delete[] F;
    delete[] G;

    return out;
}

// --------------- main ---------------
int main(){
    int n=3, t=2;

    // Setup
    TIACParams p = setupParams();

    // Test e(g1,g2)
    element_t tmpGT;
    element_init_GT(tmpGT, p.pairing);
    pairing_apply(tmpGT, p.g1, p.g2, p.pairing);

    char* strP = mpz_get_str(nullptr,10, p.prime_order);
    std::cout<<"p = "<<strP<<"\n"; free(strP);

    {
        char buf[2048];
        element_snprintf(buf,sizeof(buf),"%B",p.g1);
        std::cout<<"g1 = "<<buf<<"\n";
        element_snprintf(buf,sizeof(buf),"%B",p.g2);
        std::cout<<"g2 = "<<buf<<"\n";
        element_snprintf(buf,sizeof(buf),"%B",tmpGT);
        std::cout<<"e(g1,g2)= "<<buf<<"\n\n";
    }
    element_clear(tmpGT);

    // KeyGen
    KeyGenOutput out = keygen(p,t,n);

    // Print mvk
    {
        char b1[2048], b2[2048], b3[2048];
        element_snprintf(b1,sizeof(b1),"%B",out.mvk.vk1);
        element_snprintf(b2,sizeof(b2),"%B",out.mvk.vk2);
        element_snprintf(b3,sizeof(b3),"%B",out.mvk.vk3);
        std::cout<<"mvk.vk1= "<<b1<<"\n";
        std::cout<<"mvk.vk2= "<<b2<<"\n";
        std::cout<<"mvk.vk3= "<<b3<<"\n\n";
    }

    // Print msgk
    {
        char a1[1024], a2[1024];
        element_snprintf(a1,sizeof(a1),"%B",out.msgk.sk1);
        element_snprintf(a2,sizeof(a2),"%B",out.msgk.sk2);
        std::cout<<"msgk.sk1= "<<a1<<"\n";
        std::cout<<"msgk.sk2= "<<a2<<"\n\n";
    }

    // Print EA keys
    for(int i=0; i<n; i++){
        std::cout<<"=== EA "<<(i+1)<<" ===\n";
        char bx[512], by[512];
        element_snprintf(bx,sizeof(bx),"%B",out.eaKeys[i].x0);
        element_snprintf(by,sizeof(by),"%B",out.eaKeys[i].y0);
        std::cout<<" x0= "<<bx<<"\n y0= "<<by<<"\n\n";
    }

    // Bellek temizle
    element_clear(out.mvk.vk1);
    element_clear(out.mvk.vk2);
    element_clear(out.mvk.vk3);
    element_clear(out.msgk.sk1);
    element_clear(out.msgk.sk2);

    for(int i=0; i<n; i++){
        element_clear(out.eaKeys[i].x0);
        element_clear(out.eaKeys[i].y0);
        for(int j=0; j<=t; j++){
            element_clear(out.eaKeys[i].Vx[j]);
            element_clear(out.eaKeys[i].Vy[j]);
            element_clear(out.eaKeys[i].Vyprime[j]);
        }
        delete[] out.eaKeys[i].Vx;
        delete[] out.eaKeys[i].Vy;
        delete[] out.eaKeys[i].Vyprime;

        element_clear(out.eaKeys[i].sgk1);
        element_clear(out.eaKeys[i].sgk2);
        element_clear(out.eaKeys[i].vki1);
        element_clear(out.eaKeys[i].vki2);
        element_clear(out.eaKeys[i].vki3);
    }
    delete[] out.eaKeys;

    element_clear(p.g1);
    element_clear(p.g2);
    mpz_clear(p.prime_order);
    pairing_clear(p.pairing);

    return 0;
}
