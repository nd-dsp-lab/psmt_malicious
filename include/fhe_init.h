#ifndef FHE_INIT_H
#define FHE_INIT_H

#pragma once

#include "openfhe.h"
#include <cstdint>
#include <vector>

// Number of threads used in multithreaded sections
const size_t MAX_NUM_CORES = 48;  // used during the encryption and the VAF operations 


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
