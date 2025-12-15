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

// See Algorithm 1 of https://eprint.iacr.org/2024/1366.pdf
std::vector<double> makeKVals(
    double alpha, double prec
) {
    std::vector<double> Kval;
    double cond = std::pow(2, -alpha);
    double k;
    while (1 - prec > cond) {
        // f(x) = x(3-x)^2/4
        k = 3 * (1 - std::pow(prec, 0.5)) / (1 - std::pow(prec, 1.5));
        Kval.push_back(k);
        prec = k * std::pow(3 - k, 2) / 4.0;
    }
    return Kval;
}

// Inverse Sqrt Algorithm
// See Algorithm 4 of https://eprint.iacr.org/2024/1366.pdf
Ciphertext<DCRTPoly> invSqrt(
    CryptoContext<DCRTPoly> cc,
    Ciphertext<DCRTPoly> ctxt,
    double alpha,
    double prec,
    double B
) {
    Ciphertext<DCRTPoly> x = ctxt->Clone();
    cc->EvalMultInPlace(x, 1./B);

    Ciphertext<DCRTPoly> a = x->Clone();
    Ciphertext<DCRTPoly> b;
    Ciphertext<DCRTPoly> ka, a2;
    double k, ksqrtk;
    double cond = std::pow(2, -alpha);

    std::vector<double> Kvals = makeKVals(alpha, prec);

    for (uint32_t i = 0; i < Kvals.size(); i++) {
        k = Kvals[i];
        ksqrtk = std::pow(k, 1.5);
        ka = cc->EvalSub(3/k, a);
        if (i == 0) {
            b = cc->EvalMult(ksqrtk / 2.0, ka);
        } else {
            cc->EvalMultInPlace(b, ksqrtk/2.0);
            b = cc->EvalMult(b, ka);
        }
        cc->EvalSquareInPlace(ka);
        cc->EvalMultInPlace(a, ksqrtk * ksqrtk  / 4.0);
        a = cc->EvalMult(a, ka);

        prec = k * std::pow( 3 - k , 2.0) / 4.0;

        if (1 - prec < cond) {
            break;
        }        
    }
    cc->EvalMultInPlace(b, std::pow(B, 0.5));
    return b;
}

// One Sample T-TEST from invSqrt
Ciphertext<DCRTPoly> oneSampleTTestCompact(
    CryptoContext<DCRTPoly> cc,
    Ciphertext<DCRTPoly> ctxt,
    uint32_t ringDim,
    uint32_t rotRange,
    double mu,
    double alpha, double prec, double B
) {
    Ciphertext<DCRTPoly> ret = ctxt->Clone();
    Ciphertext<DCRTPoly> _tmp;
    for (uint32_t i = 1; i < ringDim; i *= 2) {
        _tmp = cc->EvalRotate(ret, i);
        cc->EvalAddInPlace(ret, _tmp);
    }    
    Ciphertext<DCRTPoly> smu = cc->EvalMult(ret, 1.0/rotRange);
    Ciphertext<DCRTPoly> sstd = cc->EvalSub(ctxt, smu);
    cc->EvalSquareInPlace(sstd);
    for (uint32_t i = 1; i < ringDim; i *= 2) {
        _tmp = cc->EvalRotate(sstd, i);
        cc->EvalAddInPlace(sstd, _tmp);
    }        
    sstd = cc->EvalMult(sstd, 1.0/((rotRange - 1) * rotRange));
    sstd = invSqrt(cc, sstd, alpha, prec, B);
    Ciphertext<DCRTPoly> T = cc->EvalSub(smu, mu);
    T = cc->EvalMult(T, sstd);
    return T;
}