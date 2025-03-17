#ifndef AGGREGATE_H
#define AGGREGATE_H

#include "setup.h"
#include "keygen.h"   // MasterVerKey tanımlı
#include "unblindsign.h"
#include <vector>
#include <string>
#include <gmp.h>
#include <pbc/pbc.h>


struct AggregateSignature {
    element_t h;           
    element_t s;          
    std::string debug_info;
};

AggregateSignature aggregateSign(
    TIACParams &params,
    const std::vector<std::pair<int, UnblindSignature>> &partialSigsWithAdmins,
    MasterVerKey &mvk,
    const std::string &didStr,
    const mpz_t groupOrder
);

#endif