#include "../include/core.h"

using namespace lbcrypto;

// Smart VAF to automatically optimize the operations 
Ciphertext<DCRTPoly> smartVAF(
    CryptoContext<DCRTPoly> cc,
    Ciphertext<DCRTPoly> ctxt,
    uint32_t n_vaf
) {
    auto ret = ctxt->Clone();

    // Automatically Select Best Operations
    // for large n_vaf, run 
    while (n_vaf >= 4) {
        ret = compVAFQuad(cc, ret);
        n_vaf -= 4;
    }

    // Remaining Computataions
    switch (n_vaf) {
        // Do Nothing
        case 0:
            break;

        // Compute Single Transformation
        case 1:
            // Compute (1.5x - 0.5) ** 2
            cc->EvalMultInPlace(ret, 1.5);
            cc->EvalSubInPlace(ret, 0.5);
            cc->EvalSquareInPlace(ret);
            break;

        // Do compVAFDouble
        case 2:
            ret = compVAFDouble(cc, ret);
            break;
        
        // Do compVAFTriple
        case 3:
            ret = compVAFTriple(cc, ret);
            break;
    }


    // Final Squaring
    for (int i = 0; i < 5; i++) {
        cc->EvalSquareInPlace(ret);
    }

    // Done!
    return ret;
}

// Fused Function for Evaluating DEP+VAF
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
) {
    auto ret = ctxt->Clone();

    // If we need to apply dep?
    if (n_dep > 0) {
        double invL_R = 1.0 / (pow(L, n_dep-1) * R);
        double coeff = pow(27.0 / 4.0, 0.5) / pow(k, 1.5);
    
        // DEP evaluation
        Ciphertext<DCRTPoly> _tmp; 
        cc->EvalMultInPlace(ret, invL_R);
        for (int i = n_dep - 1; i >= 0; i--) {
            _tmp = cc->EvalSquare(ret);
            _tmp = cc->EvalSub(k, _tmp);
    
            if (i > 0) {
                cc->EvalMultInPlace(ret, L * coeff);
            } else {
                // Precomputation of \sqrt(3/2) / R
                cc->EvalMultInPlace(ret, coeff * pow(1.5, 0.5));
            }
            ret = cc->EvalMult(ret, _tmp);
        }
    } else {
        // Multiply \sqrt(3/2) / R
        cc->EvalMultInPlace(ret, pow(1.5, 0.5) / R);
    }

    // VAF Evaluation
    // Base Function: (1 - 1.5 x^2)^2; We already handled the term "1.5"
    cc->EvalSquareInPlace(ret);
    ret = cc->EvalSub(1.0, ret);
    cc->EvalSquareInPlace(ret);

    // Smart VAF Computation
    if (isNewVAF) {
        ret = smartVAF(cc, ret, n_vaf);
    } else {
        for (uint32_t i = 0; i < n_vaf; i++) {
            cc->EvalSquareInPlace(ret);
        }
    }

    

    // (Optional) Cleanse
    for (uint32_t i = 0; i < n_cleanse; i++) {
        ret = cleanse(cc, ret);
    }

    // Return the output
    return ret;
}

Ciphertext<DCRTPoly> fusedVAFfromParams(
    CryptoContext<DCRTPoly> cc,
    Ciphertext<DCRTPoly> ctxt,
    VAFParams params
) {
    return fusedVAF(
        cc, ctxt,
        params.k, params.L, params.R, params.n_dep,
        params.n_vaf, params.n_cleanse, params.isNewVAF
    );
}


void setupVAFParams(double sigma, double kappa, int& domain, double& k, int& L, double& R, int& n_dep, int& n_vaf, int& depth, bool& isNewVAF) {
    
    int exponent = sigma / kappa; // integer division
    domain   = 1 << exponent; // 2^exponent


    if ((int)sigma == 64) {
        switch (domain) {
            case 2:   k = 4.5; L = 2; R = 2; n_dep = 0; n_vaf = 4; depth = 7 + 6 + 1; isNewVAF = false; break;
            case 4:   k = 4.5; L = 2; R = 4; n_dep = 0; n_vaf = 7; depth = 10 + 5 + 1; isNewVAF = false; break;
            case 16:  k = 4.5; L = 2; R = 16; n_dep = 0; n_vaf = 4; depth = 19 + 3 + 1; isNewVAF = true; break;
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
            case 256: k = 17; L = 4; R = 4; n_dep = 3; n_vaf = 4; depth = 19 + 4 + 1; isNewVAF = true; break;
            case 65536: k = 17; L = 4; R = 5112.73; n_dep = 2; n_vaf = 16; depth = 32 + 3 + 1; isNewVAF = true; break;
            default: std::cerr << "No matching VAF parameters for domain = " << domain << ". Using default." << std::endl;
                     k = 1; L = 1; R = 1; n_dep = 0; n_vaf = 1; depth = 1; isNewVAF = false;
        }
    }
}
