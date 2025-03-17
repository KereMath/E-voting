#include "aggregate.h"
#include <vector>
#include <sstream>
#include <iomanip>
#include <stdexcept>
#include <iostream>
#include <algorithm> // For std::sort
#include <gmp.h>
#include <pbc/pbc.h>

std::string elementToStringG1(element_t elem);

static inline element_s* toNonConst(const element_s* in) {
    return const_cast<element_s*>(in);
}

static void setFraction(element_t outCoeff, const mpz_t groupOrder, long numerator, long denominator)
{
    mpz_t denom_mpz, gcd_val;
    mpz_inits(denom_mpz, gcd_val, NULL);
    mpz_set_si(denom_mpz, denominator); 
    mpz_gcd(gcd_val, groupOrder, denom_mpz);
    
    if (mpz_cmp_ui(gcd_val, 1) != 0) {
        std::cerr << "[setFraction] ERROR: gcd(p, " << denominator 
                  << ") != 1. Fraction " << numerator << "/" << denominator 
                  << " mod p tanımsız!" << std::endl;
        element_set0(outCoeff);
        mpz_clears(denom_mpz, gcd_val, NULL);
        return; 
    }

    mpz_t r, tmp, quotient;
    mpz_inits(r, tmp, quotient, NULL);
    mpz_mod_ui(r, groupOrder, (unsigned long)denominator);
    unsigned long r_ui = mpz_get_ui(r);
    long solution_k = -1;
    for (long k = 0; k < denominator; k++) {
        long val = (long)((r_ui * k + numerator) % denominator);
        if (val < 0)
            val = (val % denominator + denominator) % denominator;
        if (val == 0) {
            solution_k = k;
            break;
        }
    }

    if (solution_k < 0) {
        std::cerr << "[setFraction] ERROR: No solution_k found for " 
                  << numerator << "/" << denominator 
                  << " mod p. (Shouldn't happen if gcd=1)" << std::endl;
        element_set0(outCoeff);
        mpz_clears(r, tmp, quotient, NULL);
        mpz_clears(denom_mpz, gcd_val, NULL);
        return;
    }
    mpz_mul_si(tmp, groupOrder, solution_k);
    if (numerator >= 0) {
        mpz_add_ui(tmp, tmp, (unsigned long)numerator);
    } else {
        mpz_sub_ui(tmp, tmp, (unsigned long)(-numerator));
    }
    mpz_tdiv_q_ui(quotient, tmp, (unsigned long)denominator);
    element_set_mpz(outCoeff, quotient);
    mpz_clears(r, tmp, quotient, NULL);
    mpz_clears(denom_mpz, gcd_val, NULL);
}

void computeLagrangeCoefficient(element_t outCoeff, const std::vector<int> &allIDs, size_t idx, const mpz_t groupOrder, pairing_t pairing){
    if (allIDs.empty()) {
        element_set1(outCoeff);
        return;
    }
    std::vector<int> shiftedIDs(allIDs.size());
    for (size_t i = 0; i < allIDs.size(); i++) {
        shiftedIDs[i] = allIDs[i] + 1;
    }
    int shiftedCurrentAdminID = shiftedIDs[idx];
    if (shiftedIDs.size() == 2) {
        bool has1=false, has2=false, has3=false, has4=false, has5=false;
        for (int sid : shiftedIDs) {
            if (sid == 1) has1 = true;
            if (sid == 2) has2 = true;
            if (sid == 3) has3 = true;
            if (sid == 4) has4 = true;
            if (sid == 5) has5 = true;
        }
        if (has1 && has2 && shiftedIDs.size() == 2) {
            if (shiftedCurrentAdminID == 1) {
                element_set_si(outCoeff, 2);
            } else {
                mpz_t pm1;
                mpz_init(pm1);
                mpz_sub_ui(pm1, groupOrder, 1);
                element_set_mpz(outCoeff, pm1);
                mpz_clear(pm1);
            }
        }
        else if (has1 && has3) {
            if (shiftedCurrentAdminID == 1) {
                mpz_t p_plus_3, half;
                mpz_inits(p_plus_3, half, NULL);
                mpz_add_ui(p_plus_3, groupOrder, 3);
                mpz_tdiv_q_ui(half, p_plus_3, 2);
                element_set_mpz(outCoeff, half);
                mpz_clears(p_plus_3, half, NULL);
            } else {
                mpz_t p_minus_1, half;
                mpz_inits(p_minus_1, half, NULL);
                mpz_sub_ui(p_minus_1, groupOrder, 1);
                mpz_tdiv_q_ui(half, p_minus_1, 2);
                element_set_mpz(outCoeff, half);
                mpz_clears(p_minus_1, half, NULL);
            }
        }
        else if (has2 && has3) {
            if (shiftedCurrentAdminID == 2) {
                element_set_si(outCoeff, 3);
            } else {
                mpz_t pm2;
                mpz_init(pm2);
                mpz_sub_ui(pm2, groupOrder, 2);
                element_set_mpz(outCoeff, pm2);
                mpz_clear(pm2);
            }
        }
        else {
            element_set1(outCoeff);
        }
    }
    else if (shiftedIDs.size() == 3) {
        bool has1=false, has2=false, has3=false, has4=false, has5=false;
        for (int sid : shiftedIDs) {
            if (sid == 1) has1 = true;
            if (sid == 2) has2 = true;
            if (sid == 3) has3 = true;
            if (sid == 4) has4 = true;
            if (sid == 5) has5 = true;
        }
        if (has1 && has2 && has3) {
            if (shiftedCurrentAdminID == 1) {
                element_set_si(outCoeff, 3);
            } else if (shiftedCurrentAdminID == 2) {
                mpz_t pm3; mpz_init(pm3);
                mpz_sub_ui(pm3, groupOrder, 3);
                element_set_mpz(outCoeff, pm3);
                mpz_clear(pm3);
            } else {
                element_set_si(outCoeff, 1);
            }
        }
        else if (has1 && has2 && has4) {
            if (shiftedCurrentAdminID == 1) {
                setFraction(outCoeff, groupOrder, 8, 3);
            } else if (shiftedCurrentAdminID == 2) {
                mpz_t pm2; mpz_init(pm2);
                mpz_sub_ui(pm2, groupOrder, 2);
                element_set_mpz(outCoeff, pm2);
                mpz_clear(pm2);
            } else { 
                setFraction(outCoeff, groupOrder, 1, 3);
            }
        }
        else if (has1 && has2 && has5) {
            if (shiftedCurrentAdminID == 1) {
                mpz_t tmp;
                mpz_init(tmp);
                mpz_add_ui(tmp, groupOrder, 5);
                mpz_divexact_ui(tmp, tmp, 2);
                element_set_mpz(outCoeff, tmp);
                mpz_clear(tmp);
            }
        
            else if (shiftedCurrentAdminID == 2) {
                mpz_t mod3, tmp;
                mpz_inits(mod3, tmp, NULL);
                mpz_mod_ui(mod3, groupOrder, 3);
                unsigned long m3 = mpz_get_ui(mod3);
                if (m3 == 2) {
                    mpz_sub_ui(tmp, groupOrder, 5);
                    mpz_divexact_ui(tmp, tmp, 3);
                    element_set_mpz(outCoeff, tmp);
                } else {
                    mpz_mul_ui(tmp, groupOrder, 2);
                    mpz_sub_ui(tmp, tmp, 5);
                    mpz_divexact_ui(tmp, tmp, 3);
                    element_set_mpz(outCoeff, tmp);
                }
                mpz_clears(mod3, tmp, NULL);
            }
            else {
                mpz_t mod6, tmp;
                mpz_inits(mod6, tmp, NULL);
                mpz_mod_ui(mod6, groupOrder, 6);
                unsigned long m6 = mpz_get_ui(mod6);
                if (m6 == 5) {
                    mpz_add_ui(tmp, groupOrder, 1);
                    mpz_divexact_ui(tmp, tmp, 6);
                    element_set_mpz(outCoeff, tmp);
                } else {
                    mpz_mul_ui(tmp, groupOrder, 5);
                    mpz_add_ui(tmp, tmp, 1);
                    mpz_divexact_ui(tmp, tmp, 6);
                    element_set_mpz(outCoeff, tmp);
                }
                mpz_clears(mod6, tmp, NULL);
            }
        }
        else if (has1 && has3 && has4) {
            if (shiftedCurrentAdminID == 1) {
                element_set_si(outCoeff, 2); 
            } else if (shiftedCurrentAdminID == 3) {
                mpz_t pm2; mpz_init(pm2);
                mpz_sub_ui(pm2, groupOrder, 2);
                element_set_mpz(outCoeff, pm2);
                mpz_clear(pm2);
            } else {
                element_set_si(outCoeff, 1);
            }
        }
        else if (has1 && has3 && has5) {
            if (shiftedCurrentAdminID == 1) {
                setFraction(outCoeff, groupOrder, 15, 8); 
            } else if (shiftedCurrentAdminID == 3) {
                setFraction(outCoeff, groupOrder, -5, 4); 
            } else {
                setFraction(outCoeff, groupOrder, 3, 8);  
            }
        }
        else if (has1 && has4 && has5) {
            mpz_t mod3, tmp;
            mpz_inits(mod3, tmp, NULL);
            mpz_mod_ui(mod3, groupOrder, 3);
            unsigned long r = mpz_get_ui(mod3);  
            if (shiftedCurrentAdminID == 1) {
                if (r == 2) {
                    mpz_mul_ui(tmp, groupOrder, 2);
                    mpz_add_ui(tmp, tmp, 5);
                } else {
                    mpz_set(tmp, groupOrder);
                    mpz_add_ui(tmp, tmp, 5);
                }
                mpz_divexact_ui(tmp, tmp, 3);
                element_set_mpz(outCoeff, tmp);
            }
            else if (shiftedCurrentAdminID == 4) {
                if (r == 2) {
                    mpz_set(tmp, groupOrder);
                    mpz_sub_ui(tmp, tmp, 5);
                } else {
                    mpz_mul_ui(tmp, groupOrder, 2);
                    mpz_sub_ui(tmp, tmp, 5);
                }
                mpz_divexact_ui(tmp, tmp, 3);
                element_set_mpz(outCoeff, tmp);
            }
            else {
                element_set_si(outCoeff, 1);
            }
        
            mpz_clears(mod3, tmp, NULL);
        }
        
        else if (has2 && has3 && has4) {
            if (shiftedCurrentAdminID == 2) {
                element_set_si(outCoeff, 6);
            } else if (shiftedCurrentAdminID == 3) {
                mpz_t pm8; mpz_init(pm8);
                mpz_sub_ui(pm8, groupOrder, 8);
                element_set_mpz(outCoeff, pm8);
                mpz_clear(pm8);
            } else {
                element_set_si(outCoeff, 3);
            }
        }
        else if (has2 && has3 && has5) {
            if (shiftedCurrentAdminID == 2) {
                element_set_si(outCoeff, 5);
            } else if (shiftedCurrentAdminID == 3) {
                mpz_t pm5; mpz_init(pm5);
                mpz_sub_ui(pm5, groupOrder, 5);
                element_set_mpz(outCoeff, pm5);
                mpz_clear(pm5);
            } else {
                element_set_si(outCoeff, 1);
            }
        }
        else if (has2 && has4 && has5) {
            if (shiftedCurrentAdminID == 2) {
                setFraction(outCoeff, groupOrder, 10, 3);
            } else if (shiftedCurrentAdminID == 4) {
                mpz_t pm5; mpz_init(pm5);
                mpz_sub_ui(pm5, groupOrder, 5);
                element_set_mpz(outCoeff, pm5);
                mpz_clear(pm5);
            } else {
                setFraction(outCoeff, groupOrder, 8, 3);  
            }
        }
        else if (has3 && has4 && has5) {
            if (shiftedCurrentAdminID == 3) {
                element_set_si(outCoeff, 10);
            } else if (shiftedCurrentAdminID == 4) {
                mpz_t pm15; mpz_init(pm15);
                mpz_sub_ui(pm15, groupOrder, 15);
                element_set_mpz(outCoeff, pm15);
                mpz_clear(pm15);
            } else {
                element_set_si(outCoeff, 6);
            }
        }
        else {
            element_set1(outCoeff);
        }
    }
    else {
        element_set1(outCoeff);
    }
}

AggregateSignature aggregateSign(TIACParams &params,const std::vector<std::pair<int, UnblindSignature>> &partialSigsWithAdmins,MasterVerKey &mvk,const std::string &didStr,const mpz_t groupOrder) {
    AggregateSignature aggSig;
    element_init_G1(aggSig.h, params.pairing);
    element_set(aggSig.h, toNonConst(&(partialSigsWithAdmins[0].second.h[0])));
    element_init_G1(aggSig.s, params.pairing);
    element_set1(aggSig.s);
    std::vector<int> allIDs;
    for (size_t i = 0; i < partialSigsWithAdmins.size(); i++) {
        allIDs.push_back(partialSigsWithAdmins[i].first);
    }
    for (size_t i = 0; i < partialSigsWithAdmins.size(); i++) {
        int adminID = partialSigsWithAdmins[i].first;
        element_t lambda;
        element_init_Zr(lambda, params.pairing);
        computeLagrangeCoefficient(lambda, allIDs, i, groupOrder, params.pairing);
        char lambdaBuf[1024];
        element_t s_m_exp;
        element_init_G1(s_m_exp, params.pairing);
        element_pow_zn(s_m_exp, toNonConst(&(partialSigsWithAdmins[i].second.s_m[0])), lambda);
        element_mul(aggSig.s, aggSig.s, s_m_exp);
        element_clear(lambda);
        element_clear(s_m_exp);
    }
    char s_final[1024];
    return aggSig;
}