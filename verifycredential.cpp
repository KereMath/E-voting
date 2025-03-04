#include "verifycredential.h"
#include <iostream>
#include <sstream>
#include <vector>
#include <iomanip>

// Dışarıdan tanımlı: elementToStringG1 (const element_t parametre alacak şekilde)
extern std::string elementToStringG1(const element_t elem);

bool verifyCredential(TIACParams &params, ProveCredentialOutput &pOut) {
    std::cout << "[VERIFY] Starting credential verification.\n";
    
    // Compute pairing: e(h'', k) and e(s'', g2)
    element_t pairing_lhs, pairing_rhs;
    element_init_GT(pairing_lhs, params.pairing);
    element_init_GT(pairing_rhs, params.pairing);
    
    pairing_apply(pairing_lhs, pOut.sigmaRnd.h, pOut.k, params.pairing);
    pairing_apply(pairing_rhs, pOut.sigmaRnd.s, params.g2, params.pairing);
    
    std::string lhsStr, rhsStr;
    {
        int len = element_length_in_bytes(pairing_lhs);
        std::vector<unsigned char> buf(len);
        element_to_bytes(buf.data(), pairing_lhs);
        std::ostringstream oss;
        oss << std::hex << std::setfill('0');
        for (auto c : buf)
            oss << std::setw(2) << (int)c;
        lhsStr = oss.str();
    }
    {
        int len = element_length_in_bytes(pairing_rhs);
        std::vector<unsigned char> buf(len);
        element_to_bytes(buf.data(), pairing_rhs);
        std::ostringstream oss;
        oss << std::hex << std::setfill('0');
        for (auto c : buf)
            oss << std::setw(2) << (int)c;
        rhsStr = oss.str();
    }
    std::cout << "[VERIFY] Pairing LHS = " << lhsStr << "\n";
    std::cout << "[VERIFY] Pairing RHS = " << rhsStr << "\n";
    
    bool valid = (element_cmp(pairing_lhs, pairing_rhs) == 0);
    
    element_clear(pairing_lhs);
    element_clear(pairing_rhs);
    
    if(valid) {
        std::cout << "[VERIFY] Credential verification PASSED.\n";
    } else {
        std::cout << "[VERIFY] Credential verification FAILED.\n";
    }
    return valid;
}
