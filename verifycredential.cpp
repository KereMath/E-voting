#include "verifycredential.h"
#include <iostream>
#include <sstream>
#include <vector>
#include <iomanip>

// Dışarıdan tanımlı: elementToStringG1 (örneğin, provecredential veya unblindsign modülünden)
extern std::string elementToStringG1(element_t elem);

// Ortak GT elemanı dönüşümü için yardımcı fonksiyon:
static std::string gtToString(element_t gt_elem) {
    int len = element_length_in_bytes(gt_elem);
    std::vector<unsigned char> buf(len);
    element_to_bytes(buf.data(), gt_elem);
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (auto c : buf) {
        oss << std::setw(2) << (int)c;
    }
    return oss.str();
}

bool verifyCredential(
    TIACParams &params,
    ProveCredentialOutput &pOut
) {
    std::cout << "[VERIFY] Starting credential verification.\n";
    
    // Compute pairing: e(h'', k) and e(s'', g2)
    element_t pairing_lhs, pairing_rhs;
    element_init_GT(pairing_lhs, params.pairing);
    element_init_GT(pairing_rhs, params.pairing);
    
    pairing_apply(pairing_lhs, pOut.sigmaRnd.h, pOut.k, params.pairing);
    pairing_apply(pairing_rhs, pOut.sigmaRnd.s, params.g2, params.pairing);
    
    // GT elemanlarını string'e dönüştürmek için aynı fonksiyonu kullanıyoruz.
    std::string lhsStr = gtToString(pairing_lhs);
    std::string rhsStr = gtToString(pairing_rhs);
    
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
