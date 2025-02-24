#include <iostream>
#include <pbc/pbc.h>
#include <gmp.h>
#include <cassert>
#include <vector>
#include <string>
#include <cstring>
// BN-256 param
static const char *BN256 = R"(
type f
q 186944716490498228592211144210229761989241675946164825413929
r 186944716490498228592211144210229761989241675946164825526319
b 1
beta 109341043287096796981443118641762728007143963588
alpha0 147354120310549301445722100263386112552812769040
alpha1 12707752274141484575335849047546472705710528192
)";


// ---------- Setup --------------
struct TIACParams {
    pairing_t pairing;
    mpz_t prime_order;
    element_t g1;
    element_t g2;
};

static TIACParams setupParams() {
    TIACParams p;
    pbc_param_t pp;
    pbc_param_init_set_buf(pp, BN256, strlen(BN256));
    pairing_init_pbc_param(p.pairing, pp);
    pbc_param_clear(pp);

    mpz_init_set(p.prime_order, p.pairing->r);

    element_init_G1(p.g1, p.pairing);
    element_init_G2(p.g2, p.pairing);

    element_random(p.g1);
    element_random(p.g2);

    // e(g1,g2) != 1
    element_t checkGT;
    element_init_GT(checkGT, p.pairing);
    pairing_apply(checkGT, p.g1, p.g2, p.pairing);
    int tries=0;
    while(element_is1(checkGT) && tries<32){
        element_random(p.g1);
        element_random(p.g2);
        pairing_apply(checkGT, p.g1, p.g2, p.pairing);
        tries++;
    }
    element_clear(checkGT);

    return p;
}


// ---------- DKG Key Structures -----------
struct EAKey {
    // sabit terim x0, y0
    element_t x0;
    element_t y0;

    // t+1 commitments
    std::vector<element_t> Vx;
    std::vector<element_t> Vy;
    std::vector<element_t> Vyprime;

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
    std::vector<EAKey> eaKeys;
};

// -------- Evaluate Poly -----------
static void evaluatePoly(element_s *coeffs, int t, int L, TIACParams &params, element_t outVal)
{
    // F_i(L) = ∑ coeffs[k]*L^k (mod r)
    element_set0(outVal);

    element_t xVal;
    element_init_Zr(xVal, params.pairing);
    element_set_si(xVal, L);

    element_t power;
    element_init_Zr(power, params.pairing);
    element_set1(power);

    element_t tmp;
    element_init_Zr(tmp, params.pairing);

    for(int k_i=0; k_i<=t; k_i++){
        element_mul(tmp, &coeffs[k_i], power);
        element_add(outVal, outVal, tmp);
        element_mul(power, power, xVal);
    }

    element_clear(xVal);
    element_clear(power);
    element_clear(tmp);
}


// ---------- KeyGen (Pedersen DKG) ---------------
KeyGenOutput keygen(TIACParams &params, int t, int n) {
    KeyGenOutput out;
    out.eaKeys.resize(n);

    // Polinom katsayıları
    element_s **F = new element_s*[n];
    element_s **G = new element_s*[n];

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

    // EA Keys: fill commitments
    for(int i=0; i<n; i++){
        out.eaKeys[i].Vx.resize(t+1);
        out.eaKeys[i].Vy.resize(t+1);
        out.eaKeys[i].Vyprime.resize(t+1);

        for(int j=0; j<=t; j++){
            element_init_G2(out.eaKeys[i].Vx[j], params.pairing);
            element_init_G2(out.eaKeys[i].Vy[j], params.pairing);
            element_init_G1(out.eaKeys[i].Vyprime[j], params.pairing);

            element_pow_zn(out.eaKeys[i].Vx[j], params.g2, &F[i][j]);
            element_pow_zn(out.eaKeys[i].Vy[j], params.g2, &G[i][j]);
            element_pow_zn(out.eaKeys[i].Vyprime[j], params.g1, &G[i][j]);
        }
    }

    // sabit terimler
    for(int i=0; i<n; i++){
        element_init_Zr(out.eaKeys[i].x0, params.pairing);
        element_set(out.eaKeys[i].x0, &F[i][0]);

        element_init_Zr(out.eaKeys[i].y0, params.pairing);
        element_set(out.eaKeys[i].y0, &G[i][0]);
    }

    // pay doğrulama
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
            evaluatePoly(F[i], t, L, params, fVal);  // F_i(L)
            evaluatePoly(G[i], t, L, params, gVal);  // G_i(L)

            // g2^F_i(L)
            element_pow_zn(lhsG2, params.g2, fVal);

            // RHS = ∏_{j=0..t} [ Vx[i][j] ^( L^j ) ]
            element_set1(rhsG2);
            long powInt=1;
            for(int j=0; j<=t; j++){
                if(j>0) powInt *= L;
                element_set_si(eExp, powInt);
                element_t tmpG2;
                element_init_G2(tmpG2, params.pairing);
                element_pow_zn(tmpG2, out.eaKeys[i].Vx[j], eExp);
                element_mul(rhsG2, rhsG2, tmpG2);
                element_clear(tmpG2);
            }
            if(element_cmp(lhsG2, rhsG2)!=0){
                std::cerr<<"[WARN] F_i("<<L<<") mismatch => i="<<i<<"\n";
            }

            // g2^G_i(L)
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

            // g1^G_i(L)
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

    // Master VK
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

    // Master SK
    element_init_Zr(out.msgk.sk1, params.pairing);
    element_init_Zr(out.msgk.sk2, params.pairing);
    element_set0(out.msgk.sk1);
    element_set0(out.msgk.sk2);

    for(int i=0; i<n; i++){
        element_add(out.msgk.sk1, out.msgk.sk1, &F[i][0]);
        element_add(out.msgk.sk2, out.msgk.sk2, &G[i][0]);
    }

    // local pay
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

    // polinom clear
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


// -------- main -----------
int main(){
    int n=3, t=2;
    TIACParams p = setupParams();

    // print p
    char *strp = mpz_get_str(nullptr,10, p.prime_order);
    std::cout<<"p = "<<strp<<"\n";
    free(strp);

    {
        char b[4096];
        element_snprintf(b,sizeof(b),"%B",p.g1);
        std::cout<<"g1 = "<<b<<"\n";
        element_snprintf(b,sizeof(b),"%B",p.g2);
        std::cout<<"g2 = "<<b<<"\n";
    }

    element_t check;
    element_init_GT(check, p.pairing);
    pairing_apply(check, p.g1, p.g2, p.pairing);
    {
        char b[4096];
        element_snprintf(b,sizeof(b),"%B",check);
        std::cout<<"e(g1,g2)= "<<b<<"\n\n";
    }
    element_clear(check);

    KeyGenOutput K = keygen(p,t,n);

    {
        char b[2048];
        element_snprintf(b,sizeof(b),"%B",K.mvk.vk1);
        std::cout<<"mvk.vk1= "<<b<<"\n";
        element_snprintf(b,sizeof(b),"%B",K.mvk.vk2);
        std::cout<<"mvk.vk2= "<<b<<"\n";
        element_snprintf(b,sizeof(b),"%B",K.mvk.vk3);
        std::cout<<"mvk.vk3= "<<b<<"\n\n";
    }

    {
        char b1[1024], b2[1024];
        element_snprintf(b1,sizeof(b1),"%B",K.msgk.sk1);
        element_snprintf(b2,sizeof(b2),"%B",K.msgk.sk2);
        std::cout<<"msgk.sk1= "<<b1<<"\n";
        std::cout<<"msgk.sk2= "<<b2<<"\n";
    }

    for(int i=0; i<n; i++){
        std::cout<<"=== EA #"<<(i+1)<<" ===\n";
        char bx[512], by[512];
        element_snprintf(bx,sizeof(bx),"%B",K.eaKeys[i].x0);
        element_snprintf(by,sizeof(by),"%B",K.eaKeys[i].y0);
        std::cout<<" x0= "<<bx<<"\n y0= "<<by<<"\n";
        std::cout<<" commitments:\n";
        for(int j=0; j<=t; j++){
            char vx[512], vy[512], vyp[512];
            element_snprintf(vx,sizeof(vx),"%B",K.eaKeys[i].Vx[j]);
            element_snprintf(vy,sizeof(vy),"%B",K.eaKeys[i].Vy[j]);
            element_snprintf(vyp,sizeof(vyp),"%B",K.eaKeys[i].Vyprime[j]);
            std::cout<<"   j="<<j<<" => Vx="<<vx<<", Vy="<<vy<<", Vy'="<<vyp<<"\n";
        }
        char s1[512], s2[512], v1[512], v2[512], v3[512];
        element_snprintf(s1,sizeof(s1),"%B",K.eaKeys[i].sgk1);
        element_snprintf(s2,sizeof(s2),"%B",K.eaKeys[i].sgk2);
        element_snprintf(v1,sizeof(v1),"%B",K.eaKeys[i].vki1);
        element_snprintf(v2,sizeof(v2),"%B",K.eaKeys[i].vki2);
        element_snprintf(v3,sizeof(v3),"%B",K.eaKeys[i].vki3);

        std::cout<<" sgk1= "<<s1<<"\n sgk2= "<<s2<<"\n";
        std::cout<<" vki1= "<<v1<<"\n vki2= "<<v2<<"\n vki3= "<<v3<<"\n\n";
    }

    // bellek clear
    element_clear(K.mvk.vk1);
    element_clear(K.mvk.vk2);
    element_clear(K.mvk.vk3);
    element_clear(K.msgk.sk1);
    element_clear(K.msgk.sk2);

    for(int i=0; i<n; i++){
        element_clear(K.eaKeys[i].x0);
        element_clear(K.eaKeys[i].y0);
        for(int j=0; j<=t; j++){
            element_clear(K.eaKeys[i].Vx[j]);
            element_clear(K.eaKeys[i].Vy[j]);
            element_clear(K.eaKeys[i].Vyprime[j]);
        }
        element_clear(K.eaKeys[i].sgk1);
        element_clear(K.eaKeys[i].sgk2);
        element_clear(K.eaKeys[i].vki1);
        element_clear(K.eaKeys[i].vki2);
        element_clear(K.eaKeys[i].vki3);
    }

    // param clearing
    element_clear(p.g1);
    element_clear(p.g2);
    mpz_clear(p.prime_order);
    pairing_clear(p.pairing);

    std::cout<<"[INFO] end.\n";
    return 0;
}
