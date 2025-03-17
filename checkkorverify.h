#ifndef CHECKKORVERIFY_H
#define CHECKKORVERIFY_H

#include "setup.h"
#include "keygen.h"         
#include "kor.h"            
#include "provecredential.h" 
#include <string>


bool checkKoRVerify(
    TIACParams &params,
    const ProveCredentialOutput &proveRes,
    const MasterVerKey &mvk,  
    const std::string &com_str,
    const element_t h_agg
);

#endif // CHECKKORVERIFY_H
