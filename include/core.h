#ifndef CORE_H
#define CORE_H

#include "openfhe.h"
#include "vaf.h"

using namespace lbcrypto;


typedef struct _VAFParams {
    // DEP parameters
    double k; double L; double R; uint32_t n_dep;
    // VAF parameters
    uint32_t n_vaf; uint32_t n_cleanse; bool isNewVAF;
} VAFParams;

// Function to set up VAF parameters
void setupVAFParams(double sigma, double kappa, int& domain, double& k, int& L, double& R, int& n_dep, int& n_vaf, int& depth, bool& isNewVAF);


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
    uint32_t n_cleanse,
    // NewVAF?
    bool isNewVAF
);

Ciphertext<DCRTPoly> fusedVAFfromParams(
    CryptoContext<DCRTPoly> cc,
    Ciphertext<DCRTPoly> ctxt,
    VAFParams params
);

#endif