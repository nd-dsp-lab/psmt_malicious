#include "server.h"
#include "../logreg/core.h"
#include "../include/core.h"

std::vector<uint64_t> chunkDataset(uint64_t item, uint32_t kappa) {
    std::vector<uint64_t> ret(kappa);
    uint64_t maskLen = 64 / kappa;
    uint64_t masking = ((uint64_t)(1) << maskLen) - 1;

    for (uint32_t i = 0; i < kappa; i++) {
        ret[kappa - i - 1] = item & masking;
        item >>= maskLen;
    }
    return ret;
}



// Dataset Generation
// Assume Label Values are already pre-processed
EncryptedDB constructDB(
    CryptoContext<DCRTPoly> cc,
    PublicKey<DCRTPoly> pk,
    std::vector<uint64_t> idMsgVec,
    std::vector<double> labMsgVec,
    double statVal,
    uint32_t kappa
) {
    // 
    uint32_t numItems = idMsgVec.size();
    // Pre-process the idMsgVec
    std::vector<std::vector<uint64_t>> chunkedDB(numItems);

    #pragma omp parallel for
    for (uint32_t i = 0; i < numItems; i++) {
        chunkedDB[i] = chunkDataset(idMsgVec[i], kappa);
    }

    // Encrypt the database and label
    // We will manage the database by each "chunks"
    uint32_t chunkSize = (1<<16) / kappa;
    uint32_t numChunk = numItems / chunkSize + (numItems % chunkSize != 0);

    std::vector<Ciphertext<DCRTPoly>> idVec(numChunk);
    std::vector<Ciphertext<DCRTPoly>> labelVec(numChunk);

    #pragma omp parallel for
    for (uint32_t i = 0; i < numChunk; i++) {
        uint32_t offset = chunkSize * i;

        // Read Database
        std::vector<double> _tmpIdVec(1<<16, 0.0);
        std::vector<double> _tmpLabVec(1<<16, 0.0);
        for (uint32_t j = 0; j < chunkSize; j++) {
            _tmpLabVec[j * kappa] = labMsgVec[offset + j];
            for (uint32_t k = 0; k < kappa; k++) {
                _tmpIdVec[j * kappa + k] = chunkedDB[offset + j][k];                
            }
        }

        // Encrypt Data
        Plaintext ptxtId = cc->MakeCKKSPackedPlaintext(_tmpIdVec);
        Plaintext ptxtLab = cc->MakeCKKSPackedPlaintext(_tmpLabVec);

        idVec[i] = cc->Encrypt(ptxtId, pk);
        labelVec[i] = cc->Encrypt(ptxtLab, pk);
    }

    // Prepare Statistics
    std::vector<double> statVec(1<<16, 0.0);
    for (uint32_t i = 0; i < chunkSize; i++) {
        statVec[i * kappa] = statVal;
    }
    Plaintext ptxtStat = cc->MakeCKKSPackedPlaintext(statVec);
    Ciphertext<DCRTPoly> stat = cc->Encrypt(ptxtStat, pk);

    // Done!
    return EncryptedDB {
        idVec, labelVec, stat, kappa
    };
}


// Useful tool
Ciphertext<DCRTPoly> preserveSlotZero(
    CryptoContext<DCRTPoly> cc,
    Ciphertext<DCRTPoly> ct,              // ciphertext with kappa number of chunks -> kappa must be a power of two    
    size_t kappa                            
) {
    size_t step = kappa >> 1; // half of kappa

    while (step > 0) {
        // 1) Rotate by step
        auto rotated = cc->EvalRotate(ct, step);

        // 2) Multiply => forces the side that lines up with zero to remain zero
        //    and keeps slot 0 if it's not aligned to zero
        ct = cc->EvalMult(ct, rotated);

        step >>= 1; // step = step / 2
    }

    return ct;
}

// Do Intersection
Ciphertext<DCRTPoly> compInter(
    CryptoContext<DCRTPoly> cc,
    VAFParams params,
    EncryptedDB DB,
    Ciphertext<DCRTPoly> queryCtxt
) {

    // Step 1. Evaluate VAF
    std::vector<Ciphertext<DCRTPoly>> vafResultVec(DB.idVec.size());
    std::vector<Ciphertext<DCRTPoly>> labResultVec(DB.idVec.size());

    // Masking Vector
    std::vector<double> _tmpVec(1<<16, 0.0);
    for (uint32_t i = 0;  i < (1<<16); i += DB.kappa) {
        _tmpVec[i] = 1;
    }
    Plaintext maskPtxt = cc->MakeCKKSPackedPlaintext(_tmpVec);
    // std::cout << DB.idVec.size() << std::endl;

    #pragma omp parallel for 
    for (uint32_t i = 0; i < DB.idVec.size(); i++) {
        vafResultVec[i] = cc->EvalSub(DB.idVec[i], queryCtxt);
        // Evaluate VAF HERE
        vafResultVec[i] = fusedVAFfromParams(cc, vafResultVec[i], params);

        // Rotation & Multiplication
        vafResultVec[i] = preserveSlotZero(cc, vafResultVec[i], DB.kappa);

        // Final Masking
        vafResultVec[i] = cc->EvalMult(vafResultVec[i], maskPtxt);

        // Label Embedding
        labResultVec[i] = cc->EvalMult(vafResultVec[i], DB.labelVec[i]);
    }
    // Additive Aggregation
    Ciphertext<DCRTPoly> vafResult = cc->EvalAddMany(vafResultVec);
    Ciphertext<DCRTPoly> labResult = cc->EvalAddMany(labResultVec);

    // std::cout << DB.kappa << std::endl;
    // std::cout << "YAY!" << std::endl;

    // Rotation & Addition
    Ciphertext<DCRTPoly> _tmp;
    for (uint32_t i = DB.kappa; i < 65536; i = i * 2) {
        _tmp = cc->EvalRotate(vafResult, i);
        vafResult = cc->EvalAdd(vafResult, _tmp);
        _tmp = cc->EvalRotate(labResult, i);
        labResult = cc->EvalAdd(labResult, _tmp);
        // std::cout << "YAY!" << std::endl;
    }

    // Choice Statistics
    Ciphertext<DCRTPoly> ret = labResult->Clone();
    _tmp = cc->EvalSub(1.0, vafResult);
    _tmp = cc->EvalMult(_tmp, DB.stat);
    cc->EvalAddInPlace(ret, _tmp);
    _tmp = cc->EvalRotate(vafResult, -1);
    cc->EvalAddInPlace(ret, _tmp);

    // Done!
    return ret;
}

// Operations for the Leader Server
LSResponse evalCircuit(
    CryptoContext<DCRTPoly> cc,
    std::vector<Ciphertext<DCRTPoly>> ctxts,
    VAFParams paramsVAF,
    LogRegParams paramsLR,
    uint32_t kappa
) {
    // Evaluate Logistic Regression
    auto evalRet = logRegEval(cc, paramsLR, ctxts);
    std::vector<double> _maskVecRet(1<<16, 0); 
    for (uint32_t i = 0; i < (1<<16); i = i + kappa) {
        _maskVecRet[i] = 1;
    }
    Plaintext maskPtxtRet = cc->MakeCKKSPackedPlaintext(_maskVecRet);
    evalRet = cc->EvalMult(evalRet, maskPtxtRet);

    // Evaluate Additive Aggregation & Extraction
    auto isInter = cc->EvalAddMany(ctxts);

    // Masking Vector
    std::vector<double> _maskVec(1<<16, 0); 
    for (uint32_t i = 1; i < (1<<16); i = i + kappa) {
        _maskVec[i] = 1;
    }
    Plaintext maskPtxt = cc->MakeCKKSPackedPlaintext(_maskVec);
    isInter = cc->EvalMult(isInter, maskPtxt);

    // Rotation & Add 
    Ciphertext<DCRTPoly> _tmp;
    for (uint32_t i = 1; i < kappa; i *= 2) {
        _tmp = cc->EvalRotate(isInter, i);
        isInter = cc->EvalAdd(isInter, _tmp);
    }

    // Do a VAF evaluation
    isInter = fusedVAFfromParams(cc, isInter, paramsVAF);
    isInter = cc->EvalSub(1.0, isInter);

    return LSResponse { evalRet, isInter };
}