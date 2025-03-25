#ifndef LR_CORE_H
#define LR_CORE_H

#include "../include/fhe_init.h"
#include "openfhe.h"
#include <vector>

using namespace lbcrypto;

typedef struct _LogRegParams {
    std::vector<Ciphertext<DCRTPoly>> weights;
    Ciphertext<DCRTPoly> bias;
    uint32_t degree;
    double a; double b;
} LogRegParams;

LogRegParams constructLRParams (
    CryptoContext<DCRTPoly> cc,
    PublicKey<DCRTPoly> pk,
    std::vector<double> ptWeights,
    double ptBias,
    // Will be removed
    uint32_t ringDim,
    uint32_t degree,
    double a, double b
);

Ciphertext<DCRTPoly> logRegEval(
    CryptoContext<DCRTPoly> cc,
    LogRegParams params,
    std::vector<Ciphertext<DCRTPoly>> ctxts
);

#endif