#ifndef CORE_H
#define CORE_H

#include "openfhe.h"
#include "vaf.h"

using namespace lbcrypto;

Ciphertext<DCRTPoly> smartVAF(
    CryptoContext<DCRTPoly> cc,
    Ciphertext<DCRTPoly> ctxt,
    uint32_t n_vaf
);

Ciphertext<DCRTPoly> fusedVAF(
    CryptoContext<DCRTPoly> cc,
    Ciphertext<DCRTPoly> ctxt,
    // DEP parameters
    double k, double L, double R, uint32_t n_dep,
    // VAF Parameters
    uint32_t n_vaf,
    // For cleanse
    uint32_t n_cleanse
);

#endif