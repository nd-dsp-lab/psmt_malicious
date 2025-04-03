#ifndef CORE_H
#define CORE_H

#include "openfhe.h"
#include "vaf.h"

using namespace lbcrypto;


typedef struct _VAFParams {
    // DEP parameters
    double k = 1; double L = 1; double R = 1; uint32_t n_dep = 0;
    // VAF parameters
    uint32_t n_vaf = 1; uint32_t depth = 1; uint32_t n_cleanse = 0; bool isNewVAF = false;

    void setupVAFParams(double sigma, double kappa) {

        int exponent = sigma / kappa; // integer division
        int domain   = 1 << exponent; // 2^exponent
    
        if ((int)sigma == 64) {
            switch (domain) {
                case 2:   k = 4.5; L = 2; R = 2; n_dep = 0; n_vaf = 4; depth = 7 + 6 + 1; isNewVAF = false; break;
                case 4:   k = 4.5; L = 2; R = 4; n_dep = 0; n_vaf = 7; depth = 10 + 5 + 1; isNewVAF = false; break;
                case 16:  k = 4.5; L = 2; R = 16; n_dep = 0; n_vaf = 4; depth = 13 + 4 + 1; isNewVAF = true; break;
                case 64:  k = 17; L = 4; R = 4; n_dep = 2; n_vaf = 3; depth = 16 + 3 + 1; isNewVAF = true; break;
                case 256: k = 17; L = 4; R = 4; n_dep = 3; n_vaf = 4; depth = 23; isNewVAF = true; break;
                case 65536: k = 17; L = 4; R = 5112.73; n_dep = 2; n_vaf = 16; depth = 32 + 2 + 1; isNewVAF = true; break;
                default: std::cerr << "No matching VAF parameters for domain = " << domain << ". Using default." << std::endl;
                         k = 1; L = 1; R = 1; n_dep = 0; n_vaf = 1; depth = 1; isNewVAF = false;
            }
        } else if ((int)sigma == 128) {
            switch (domain) {
                case 2:   k = 4.5; L = 2; R = 2; n_dep = 0; n_vaf = 4; depth = 7 + 7 + 1; isNewVAF = false; break;
                case 4:   k = 4.5; L = 2; R = 4; n_dep = 0; n_vaf = 7; depth = 10 + 6 + 1; isNewVAF = false; break;
                case 16:  k = 4.5; L = 2; R = 16; n_dep = 0; n_vaf = 4; depth = 13 + 5 + 1; isNewVAF = true; break;
                case 64:  k = 17; L = 4; R = 4; n_dep = 2; n_vaf = 3; depth = 16 + 4 + 1; isNewVAF = true; break;
                case 256: k = 17; L = 4; R = 4; n_dep = 3; n_vaf = 4; depth = 19 + 4 + 1; isNewVAF = true; break;
                case 65536: k = 17; L = 4; R = 5112.73; n_dep = 2; n_vaf = 16; depth = 32 + 3 + 1; isNewVAF = true; break;
                default: std::cerr << "No matching VAF parameters for domain = " << domain << ". Using default." << std::endl;
                         k = 1; L = 1; R = 1; n_dep = 0; n_vaf = 1; depth = 1; isNewVAF = false;
            }
        }
    }    

    void setupVAFParamfromDomain(int domain) {
        switch (domain) {
            case 2:   k = 4.5; L = 2; R = 2; n_dep = 0; n_vaf = 4; depth = 7 + 6 + 1; isNewVAF = false; break;
            case 4:   k = 4.5; L = 2; R = 4; n_dep = 0; n_vaf = 7; depth = 10 + 5 + 1; isNewVAF = false; break;
            case 16:  k = 4.5; L = 2; R = 16; n_dep = 0; n_vaf = 4; depth = 19 + 3 + 1; isNewVAF = true; break;
            case 64:  k = 17; L = 4; R = 4; n_dep = 2; n_vaf = 3; depth = 16 + 3 + 1; isNewVAF = true; break;
            case 256: k = 17; L = 4; R = 4; n_dep = 3; n_vaf = 4; depth = 23; isNewVAF = true; break;
            case 65536: k = 17; L = 4; R = 5112.73; n_dep = 2; n_vaf = 16; depth = 32 + 2 + 1; isNewVAF = true; break;
            default: std::cerr << "No matching VAF parameters for domain = " << domain << ". Using default." << std::endl;
                     k = 1; L = 1; R = 1; n_dep = 0; n_vaf = 1; depth = 1; isNewVAF = false;
        }
    }
} VAFParams;

// Function to set up VAF parameters
void setupVAFParams(double sigma, double kappa, int& domain, double& k, double& L, double& R, int& n_dep, int& n_vaf, int& depth, bool& isNewVAF);

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
