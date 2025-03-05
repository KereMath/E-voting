// UnblindResultsWithAdmin.h
#ifndef UNBLIND_RESULTS_WITH_ADMIN_H
#define UNBLIND_RESULTS_WITH_ADMIN_H

#include "unblindsign.h"

struct UnblindSignatureWithAdmin {
    int adminId;              // İmza üreten adminin ID'si (0-indexed; yazdırırken +1 eklenir)
    UnblindSignature signature; // İlgili unblind imza
};

#endif
