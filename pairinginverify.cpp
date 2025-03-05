#include "pairinginverify.h"
#include <iostream>
#include <sstream>
#include <vector>
#include <iomanip>

// Dışarıdan tanımlı: elementToStringG1 (const parametre alır)
extern std::string elementToStringG1(const element_t elem);

bool pairingCheck(TIACParams &params, ProveCredentialOutput &pOut) {
    std::cout << "[PAIRING CHECK] Starting pairing check...\n";

    // Pairing hesaplamalarını yap: LHS = e(h'', k), RHS = e(s'', g2)
    element_t pairing_lhs, pairing_rhs;
    element_init_GT(pairing_lhs, params.pairing);
    element_init_GT(pairing_rhs, params.pairing);

    pairing_apply(pairing_lhs, pOut.sigmaRnd.h, pOut.k, params.pairing);
    pairing_apply(pairing_rhs, pOut.sigmaRnd.s, params.g2, params.pairing);

    // Debug: GT elemanlarını string'e çevirip yazdırıyoruz.
    auto gtToString = [&params](element_t gt_elem) -> std::string {
        int len = element_length_in_bytes(gt_elem);
        std::vector<unsigned char> buf(len);
        element_to_bytes(buf.data(), gt_elem);
        std::ostringstream oss;
        oss << std::hex << std::setfill('0');
        for (auto c : buf)
            oss << std::setw(2) << (int)c;
        return oss.str();
    };

    std::string lhsStr = gtToString(pairing_lhs);
    std::string rhsStr = gtToString(pairing_rhs);

    std::cout << "[PAIRING CHECK] Pairing LHS = " << lhsStr << "\n";
    std::cout << "[PAIRING CHECK] Pairing RHS = " << rhsStr << "\n";

    bool valid = (element_cmp(pairing_lhs, pairing_rhs) == 0);
    if (valid)
        std::cout << "[PAIRING CHECK] Pairing correct: e(h'', k) equals e(s'', g2).\n";
    else
        std::cout << "[PAIRING CHECK] Pairing failed: e(h'', k) does not equal e(s'', g2).\n";

    element_clear(pairing_lhs);
    element_clear(pairing_rhs);

    return valid;
}
