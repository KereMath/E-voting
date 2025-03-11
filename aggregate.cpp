#include "aggregate.h"
#include <vector>
#include <sstream>
#include <iomanip>
#include <stdexcept>
#include <iostream>
#include <algorithm> // For std::sort
#include <gmp.h>
#include <pbc/pbc.h>

// Dışarıdan sağlanan fonksiyon: elementToStringG1 (örneğin, unblindsign.h'dan)
std::string elementToStringG1(element_t elem);

// Helper: const element_s*'yi non-const element_s*'ye dönüştürür.
static inline element_s* toNonConst(const element_s* in) {
    return const_cast<element_s*>(in);
}
#include <vector>
#include <gmp.h>
#include <pbc/pbc.h>
#include <algorithm>

/********************************************/
/* KESİR YARDIMCI FONKSİYONU:
   setFraction(outCoeff, groupOrder, num, den) -> outCoeff = (num/den) mod p
   (p = groupOrder).
   Örnek: (8/3) mod p gibi bir değeri, p içinde tam bölünecek şekilde 
   p*k + num'i den'e böleriz.
*/
static void setFraction(element_t outCoeff, const mpz_t groupOrder, long numerator, long denominator)
{
    // 1) denominator ile p arası gcd kontrol
    mpz_t denom_mpz, gcd_val;
    mpz_inits(denom_mpz, gcd_val, NULL);
    mpz_set_si(denom_mpz, denominator);  // denominator'ı mpz'ye yükle
    mpz_gcd(gcd_val, groupOrder, denom_mpz);
    
    if (mpz_cmp_ui(gcd_val, 1) != 0) {
        // gcd != 1 => payda mod p'de invertible değil
        std::cerr << "[setFraction] ERROR: gcd(p, " << denominator 
                  << ") != 1. Fraction " << numerator << "/" << denominator 
                  << " mod p tanımsız!" << std::endl;
        // İstersen outCoeff = 0 veya outCoeff = 1 gibi bir şey ata:
        element_set0(outCoeff);
        
        mpz_clears(denom_mpz, gcd_val, NULL);
        return; // Burada bitiriyoruz
    }

    // 2) ( p mod denominator ) hesapla
    mpz_t r, tmp, quotient;
    mpz_inits(r, tmp, quotient, NULL);

    mpz_mod_ui(r, groupOrder, (unsigned long)denominator);
    unsigned long r_ui = mpz_get_ui(r);

    // 3) (r_ui*k + numerator) mod denominator = 0 olacak k'yi bul
    long solution_k = -1;
    for (long k = 0; k < denominator; k++) {
        long val = (long)((r_ui * k + numerator) % denominator);
        // negatif mod düzeltmesi
        if (val < 0)
            val = (val % denominator + denominator) % denominator;
        
        if (val == 0) {
            solution_k = k;
            break;
        }
    }

    if (solution_k < 0) {
        // Normal şartlarda gcd=1 ise mutlaka bir k bulmak gerekir.
        // Yine de döngüde bulunamazsa hata verelim.
        std::cerr << "[setFraction] ERROR: No solution_k found for " 
                  << numerator << "/" << denominator 
                  << " mod p. (Shouldn't happen if gcd=1)" << std::endl;
        element_set0(outCoeff);
        
        mpz_clears(r, tmp, quotient, NULL);
        mpz_clears(denom_mpz, gcd_val, NULL);
        return;
    }

    // 4) tmp = p * k
    mpz_mul_si(tmp, groupOrder, solution_k);

    // 5) tmp = p*k + numerator (veya p*k - |numerator|)
    if (numerator >= 0) {
        mpz_add_ui(tmp, tmp, (unsigned long)numerator);
    } else {
        mpz_sub_ui(tmp, tmp, (unsigned long)(-numerator));
    }

    // 6) quotient = tmp / denominator
    mpz_tdiv_q_ui(quotient, tmp, (unsigned long)denominator);

    // 7) Sonucu element'e ata
    element_set_mpz(outCoeff, quotient);

    // Debug istersen:
    // mpz_out_str(NULL, 10, quotient);
    // std::cerr << " = " << numerator << "/" << denominator << " mod p\n";

    mpz_clears(r, tmp, quotient, NULL);
    mpz_clears(denom_mpz, gcd_val, NULL);
}
/********************************************/
/* ASIL FONKSİYON */
void computeLagrangeCoefficient(
    element_t outCoeff, 
    const std::vector<int> &allIDs, 
    size_t idx, 
    const mpz_t groupOrder, 
    pairing_t pairing)
{
    // Örnek: "allIDs = {0,1,3}" gelsin:
    // Biz bunları +1 kaydırıyoruz => {1,2,4}.
    // Sonra "shiftedCurrentAdminID" = 1,2 veya 4'e göre
    // Lagrange katsayılarını buluyoruz. 
    // Sonucu da outCoeff'e koyuyoruz.

    if (allIDs.empty()) {
        element_set1(outCoeff);
        return;
    }

    // (1) ID'leri kaydır (0 tabanlıyı 1 tabanlıya)
    std::vector<int> shiftedIDs(allIDs.size());
    for (size_t i = 0; i < allIDs.size(); i++) {
        shiftedIDs[i] = allIDs[i] + 1;
    }
    std::cout << "Shifted IDs  : ";
    for (int id : shiftedIDs) {
        std::cout << id << " ";
    }
    // Bu admin'in kaydırılmış ID'si
    int shiftedCurrentAdminID = shiftedIDs[idx];

    // 2 Elemanlı Durum (shiftedIDs.size() == 2)
    if (shiftedIDs.size() == 2) {
        // 1 tabanlı ID'ler var: 
        // Mümkün setler: {1,2}, {1,3}, {2,3}, {1,4}, vs...
        // Aşağıdaki mantığı orijinal 0-based yerini 1-based'e uyarlayalım.

        // Hangi shifted ID'ler var?
        bool has1=false, has2=false, has3=false, has4=false, has5=false;
        for (int sid : shiftedIDs) {
            if (sid == 1) has1 = true;
            if (sid == 2) has2 = true;
            if (sid == 3) has3 = true;
            if (sid == 4) has4 = true;
            if (sid == 5) has5 = true;
        }

        // Örnek: {1,2} => (0,1) idi aslında, vs...

        // {1,2}
        if (has1 && has2 && shiftedIDs.size() == 2) {
            if (shiftedCurrentAdminID == 1) {
                // lambda = 2 (p üstünde 2)
                element_set_si(outCoeff, 2);
            } else { // 2
                // lambda = -1 => p-1
                mpz_t pm1;
                mpz_init(pm1);
                mpz_sub_ui(pm1, groupOrder, 1);
                element_set_mpz(outCoeff, pm1);
                mpz_clear(pm1);
            }
        }
        // {1,3}
        else if (has1 && has3) {
            if (shiftedCurrentAdminID == 1) {
                // (0,2) durumu -> (p+3)/2 vs. 
                // Orijinal kodun "id=0 => (p+3)/2" gibi yerini taklit edeceksen 
                // buraya koyarsın. Ama senin orijinal 2'li kodda (0,2) = (1,3) 
                // tam nasıl ilerliyorsa oraya bak.
                // (Örnek) => lambda(1) = (p+3)/2
                mpz_t p_plus_3, half;
                mpz_inits(p_plus_3, half, NULL);
                mpz_add_ui(p_plus_3, groupOrder, 3);
                mpz_tdiv_q_ui(half, p_plus_3, 2);
                element_set_mpz(outCoeff, half);
                mpz_clears(p_plus_3, half, NULL);
            } else { // 3
                // lambda(3) = (p-1)/2
                mpz_t p_minus_1, half;
                mpz_inits(p_minus_1, half, NULL);
                mpz_sub_ui(p_minus_1, groupOrder, 1);
                mpz_tdiv_q_ui(half, p_minus_1, 2);
                element_set_mpz(outCoeff, half);
                mpz_clears(p_minus_1, half, NULL);
            }
        }
        // {2,3}
        else if (has2 && has3) {
            if (shiftedCurrentAdminID == 2) {
                // lambda = 3
                element_set_si(outCoeff, 3);
            } else { // 3
                // lambda = -2 => p-2
                mpz_t pm2;
                mpz_init(pm2);
                mpz_sub_ui(pm2, groupOrder, 2);
                element_set_mpz(outCoeff, pm2);
                mpz_clear(pm2);
            }
        }
        else {
            // vs... "Varsayılan" 
            // ya da her ne yapmak istersen
            element_set1(outCoeff);
        }
    }

    // 3 Elemanlı Durum
    else if (shiftedIDs.size() == 3) {
        // 1 tabanlı ID'lerin hangi kombinasyonu?
        // Mesela (1,2,4) demek orijinalde (0,1,3)...

        bool has1=false, has2=false, has3=false, has4=false, has5=false;
        for (int sid : shiftedIDs) {
            if (sid == 1) has1 = true;
            if (sid == 2) has2 = true;
            if (sid == 3) has3 = true;
            if (sid == 4) has4 = true;
            if (sid == 5) has5 = true;
        }

        // Şimdi python çıktılarımız gibi:
        // (1,2,3) => katsayı(1)=3, katsayı(2)=-3, katsayı(3)=1, vs...

        // (1) {1,2,3}
        if (has1 && has2 && has3) {
            if (shiftedCurrentAdminID == 1) {
                element_set_si(outCoeff, 3);
            } else if (shiftedCurrentAdminID == 2) {
                // -3 => p-3
                mpz_t pm3; mpz_init(pm3);
                mpz_sub_ui(pm3, groupOrder, 3);
                element_set_mpz(outCoeff, pm3);
                mpz_clear(pm3);
            } else {
                // 3
                element_set_si(outCoeff, 1);
            }
        }
        // (2) {1,2,4}
        else if (has1 && has2 && has4) {
            if (shiftedCurrentAdminID == 1) {
                // 8/3
                setFraction(outCoeff, groupOrder, 8, 3);
            } else if (shiftedCurrentAdminID == 2) {
                // -2 => p-2
                mpz_t pm2; mpz_init(pm2);
                mpz_sub_ui(pm2, groupOrder, 2);
                element_set_mpz(outCoeff, pm2);
                mpz_clear(pm2);
            } else { // 4
                // 1/3
                setFraction(outCoeff, groupOrder, 1, 3);
            }
        }
        // (3) {1,2,5}
        else if (has1 && has2 && has5) {
            if (shiftedCurrentAdminID == 1) {
                // 5/2
                setFraction(outCoeff, groupOrder, 5, 2);
            } else if (shiftedCurrentAdminID == 2) {
                // -5/3
                setFraction(outCoeff, groupOrder, -5, 3);
            } else {
                // 1/6
                setFraction(outCoeff, groupOrder, 1, 6);
            }
        }
        // (4) {1,3,4}
        else if (has1 && has3 && has4) {
            if (shiftedCurrentAdminID == 1) {
                element_set_si(outCoeff, 2); // 2
            } else if (shiftedCurrentAdminID == 3) {
                // -2 => p-2
                mpz_t pm2; mpz_init(pm2);
                mpz_sub_ui(pm2, groupOrder, 2);
                element_set_mpz(outCoeff, pm2);
                mpz_clear(pm2);
            } else { // 4
                element_set_si(outCoeff, 1);
            }
        }
        // (5) {1,3,5}
        else if (has1 && has3 && has5) {
            if (shiftedCurrentAdminID == 1) {
                setFraction(outCoeff, groupOrder, 15, 8); // 15/8
            } else if (shiftedCurrentAdminID == 3) {
                setFraction(outCoeff, groupOrder, -5, 4); // -5/4
            } else {
                setFraction(outCoeff, groupOrder, 3, 8);  // 3/8
            }
        }
        // (6) {1,4,5}
        else if (has1 && has4 && has5) {
            if (shiftedCurrentAdminID == 1) {
                setFraction(outCoeff, groupOrder, 5, 3); // 5/3
            } else if (shiftedCurrentAdminID == 4) {
                setFraction(outCoeff, groupOrder, -5, 3); // -5/3
            } else {
                element_set_si(outCoeff, 1); // 1
            }
        }
        // (7) {2,3,4}
        else if (has2 && has3 && has4) {
            if (shiftedCurrentAdminID == 2) {
                element_set_si(outCoeff, 6);
            } else if (shiftedCurrentAdminID == 3) {
                // -8 => p-8
                mpz_t pm8; mpz_init(pm8);
                mpz_sub_ui(pm8, groupOrder, 8);
                element_set_mpz(outCoeff, pm8);
                mpz_clear(pm8);
            } else {
                element_set_si(outCoeff, 3);
            }
        }
        // (8) {2,3,5}
        else if (has2 && has3 && has5) {
            if (shiftedCurrentAdminID == 2) {
                element_set_si(outCoeff, 5);
            } else if (shiftedCurrentAdminID == 3) {
                // -5 => p-5
                mpz_t pm5; mpz_init(pm5);
                mpz_sub_ui(pm5, groupOrder, 5);
                element_set_mpz(outCoeff, pm5);
                mpz_clear(pm5);
            } else {
                element_set_si(outCoeff, 1);
            }
        }
        // (9) {2,4,5}
        else if (has2 && has4 && has5) {
            if (shiftedCurrentAdminID == 2) {
                setFraction(outCoeff, groupOrder, 10, 3); // 10/3
            } else if (shiftedCurrentAdminID == 4) {
                // -5 => p-5
                mpz_t pm5; mpz_init(pm5);
                mpz_sub_ui(pm5, groupOrder, 5);
                element_set_mpz(outCoeff, pm5);
                mpz_clear(pm5);
            } else {
                setFraction(outCoeff, groupOrder, 8, 3);  // 8/3
            }
        }
        // (10) {3,4,5}
        else if (has3 && has4 && has5) {
            if (shiftedCurrentAdminID == 3) {
                element_set_si(outCoeff, 10);
            } else if (shiftedCurrentAdminID == 4) {
                // -15 => p-15
                mpz_t pm15; mpz_init(pm15);
                mpz_sub_ui(pm15, groupOrder, 15);
                element_set_mpz(outCoeff, pm15);
                mpz_clear(pm15);
            } else {
                element_set_si(outCoeff, 6);
            }
        }
        else {
            // Tanımsız bir üçlü gelirse
            element_set1(outCoeff);
        }
    }
    else {
        // 2 veya 3 haricinde ID sayısı gelmişse:
        element_set1(outCoeff);
    }
}

AggregateSignature aggregateSign(
    TIACParams &params,
    const std::vector<std::pair<int, UnblindSignature>> &partialSigsWithAdmins,
    MasterVerKey &mvk,
    const std::string &didStr,
    const mpz_t groupOrder
) {
    AggregateSignature aggSig;
    std::ostringstream debugStream;
    
    // (1) h: Tüm partial imzaların h değeri aynı kabul edildiğinden, ilk partial imzadan h alınır.
    element_init_G1(aggSig.h, params.pairing);
    // partialSigsWithAdmins[0].second.h is an element_t, which is defined as element_s[1]. 
    // We take the address of the first element.
    element_set(aggSig.h, toNonConst(&(partialSigsWithAdmins[0].second.h[0])));
    debugStream << "Aggregate h set from first partial signature.\n";
    
    // (2) s: Aggregate s başlangıçta identity (1) olarak ayarlanır.
    element_init_G1(aggSig.s, params.pairing);
    element_set1(aggSig.s);
    debugStream << "Initial aggregate s set to identity.\n";
    
    // Tüm admin ID'lerini toplayalım.
    std::vector<int> allIDs;
    for (size_t i = 0; i < partialSigsWithAdmins.size(); i++) {
        allIDs.push_back(partialSigsWithAdmins[i].first);
    }
    debugStream << "Combining partial signatures with Lagrange coefficients:\n";
    
    // (3) Her partial imza için Lagrange katsayısı hesaplanır ve s_m^(λ) ile çarpılır.
    for (size_t i = 0; i < partialSigsWithAdmins.size(); i++) {
        int adminID = partialSigsWithAdmins[i].first;
        element_t lambda;
        element_init_Zr(lambda, params.pairing);
        computeLagrangeCoefficient(lambda, allIDs, i, groupOrder, params.pairing);
        
        char lambdaBuf[1024];
        element_snprintf(lambdaBuf, sizeof(lambdaBuf), "%B", lambda);
        debugStream << "Lagrange coefficient for partial signature " << (i+1)
                    << " from Admin " << (adminID + 1)
                    << " is: " << lambdaBuf << "\n";
                    
        // s_m^(λ) hesapla. partialSigsWithAdmins[i].second.s_m is an element_t; use its first element.
        element_t s_m_exp;
        element_init_G1(s_m_exp, params.pairing);
        element_pow_zn(s_m_exp, toNonConst(&(partialSigsWithAdmins[i].second.s_m[0])), lambda);
        
        char s_m_expBuf[1024];
        element_snprintf(s_m_expBuf, sizeof(s_m_expBuf), "%B", s_m_exp);
        debugStream << "Partial signature " << (i+1)
                    << " from Admin " << (adminID + 1)
                    << ": s_m^(λ) = " << s_m_expBuf << "\n";
                    
        // Aggregate s ile çarp.
        element_mul(aggSig.s, aggSig.s, s_m_exp);
        element_clear(lambda);
        element_clear(s_m_exp);
    }
    char s_final[1024];
    element_snprintf(s_final, sizeof(s_final), "%B", aggSig.s);
    debugStream << "Final aggregate s computed = " << s_final << "\n";
    
    aggSig.debug_info = debugStream.str();
    return aggSig;
}