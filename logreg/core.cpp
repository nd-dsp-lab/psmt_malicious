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

LogRegParamsCompact constructLRParamsCompact (
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
    uint32_t rotRange = std::pow(2, std::ceil(std::log2(numWeights)));

    // Encrypt Weights 
    ptWeights.resize(1<<16, 0);
    Plaintext _tmp = cc->MakeCKKSPackedPlaintext(ptWeights);
    Ciphertext<DCRTPoly> weight = cc->Encrypt(_tmp, pk);

    // Encrypted Bias Vector
    std::vector<double> biasVec(numWeights, ptBias);
    biasVec.resize(1<<16, 0);
    _tmp = cc->MakeCKKSPackedPlaintext(biasVec);
    Ciphertext<DCRTPoly> bias = cc->Encrypt(_tmp, pk);

    return LogRegParamsCompact {
        weight, bias, rotRange, degree, a, b
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


// Logistic Regression Evaluation for compactly packed ciphertexts
Ciphertext<DCRTPoly> logRegEvalCompact(
    CryptoContext<DCRTPoly> cc,
    LogRegParamsCompact params,
    Ciphertext<DCRTPoly> ctxt
) {
    // Step 1. Do Inner Product and add bias
    Ciphertext<DCRTPoly> ret = cc->EvalMult(ctxt, params.weight);
    Ciphertext<DCRTPoly> _tmp;
    for (uint32_t i = 1; i < params.rotRange; i *= 2) {
        _tmp = cc->EvalRotate(ret, i);
        cc->EvalAddInPlace(ret, _tmp);
    }
    cc->EvalAddInPlace(ret, params.bias);

    // Step 2. Apply a sigmoid function
    ret = cc->EvalLogistic(
        ret, params.a, params.b, params.degree
    );

    // Only a first slot contains the valid result
    std::vector<double> maskVec(1<<16, 0); maskVec[0] = 1;
    Plaintext _ptxt = cc->MakeCKKSPackedPlaintext(maskVec);
    ret = cc->EvalMult(ret, _ptxt);

    return ret;
}