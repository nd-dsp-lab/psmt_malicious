#include "core.h"

// Prepare Parameters
LogRegParams constructLRParams (
    CryptoContext<DCRTPoly> cc,
    PublicKey<DCRTPoly> pk,
    std::vector<double> ptWeights,
    double ptBias,
    // Will be removed
    uint32_t ringDim,
    uint32_t degree,
    double a, double b
) {
    uint32_t numWeights = ptWeights.size();
    
    // Encrypt Weights 
    std::vector<Ciphertext<DCRTPoly>> weights(numWeights);

    #pragma omp parallel for
    for (uint32_t i = 0; i < numWeights; i++) {
        std::vector<double> msgVec(ringDim, ptWeights[i]);
        Plaintext ptxt = cc->MakeCKKSPackedPlaintext(msgVec);
        weights[i] = cc->Encrypt(ptxt, pk);
    }

    // Encrypted Bias Vector
    std::vector<double> biasVec(ringDim, ptBias);
    Plaintext ptxt = cc->MakeCKKSPackedPlaintext(biasVec);
    Ciphertext<DCRTPoly> bias = cc->Encrypt(ptxt, pk);

    return LogRegParams {
        weights, bias, degree, a, b
    };
}


// Logistic Regression Evaluation
Ciphertext<DCRTPoly> logRegEval(
    CryptoContext<DCRTPoly> cc,
    LogRegParams params,
    std::vector<Ciphertext<DCRTPoly>> ctxts
) {
    uint32_t numWeights = params.weights.size();

    if (numWeights != ctxts.size()) {
        throw std::runtime_error("Size Mismatch!");
    }

    // Step 1. Do Inner Product
    std::vector<Ciphertext<DCRTPoly>> mulVec(numWeights);

    #pragma omp parallel for
    for (uint32_t i = 0; i < numWeights; i++) {
        mulVec[i] = cc->EvalMult(ctxts[i], params.weights[i]);
    }

    mulVec.push_back(params.bias);
    auto beforeSigmoid = cc->EvalAddMany(mulVec);

    // Step 2. Apply a sigmoid function
    auto ret = cc->EvalLogistic(
        beforeSigmoid, params.a, params.b, params.degree
    );

    // Done!
    return ret;
}

// 1, 4, 8
// https://github.com/amazon-science/fraud-dataset-benchmark