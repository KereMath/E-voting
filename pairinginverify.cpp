#include "pairinginverify.h"
#include <iostream>
#include <sstream>
#include <vector>
#include <iomanip>

extern std::string elementToStringG1(const element_t elem);
bool pairingCheck(TIACParams &params, ProveCredentialOutput &pOut) {
    element_t pairing_lhs, pairing_rhs;
    element_init_GT(pairing_lhs, params.pairing);
    element_init_GT(pairing_rhs, params.pairing);
    pairing_apply(pairing_lhs, pOut.sigmaRnd.h, pOut.k, params.pairing);
    pairing_apply(pairing_rhs, pOut.sigmaRnd.s, params.g2, params.pairing);
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
    bool valid = (element_cmp(pairing_lhs, pairing_rhs) == 0);
    element_clear(pairing_lhs);
    element_clear(pairing_rhs);
    return valid;
}
