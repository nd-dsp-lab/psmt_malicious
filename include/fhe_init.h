#ifndef FHE_INIT_H
#define FHE_INIT_H

#include "openfhe.h"
#include <cstdint>
#include <vector>

// Structure for tunable FHE parameters.
struct FHEParams {
    uint32_t multiplicativeDepth;
    uint32_t scalingModSize;
    uint32_t firstModSize;
    uint32_t ringDim;
};

// Container for CryptoContext and key pair.
struct FHEContext {
    lbcrypto::CryptoContext<lbcrypto::DCRTPoly> cryptoContext;
    lbcrypto::KeyPair<lbcrypto::DCRTPoly> keyPair;
};

// Initializes the FHE system based on supplied parameters.
FHEContext InitFHE(const FHEParams &params);

#endif // FHE_INIT_H
