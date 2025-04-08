#include "server.h"
#include "../logreg/core.h"
#include "../include/core.h"

std::vector<uint64_t> chunkDataset(
    std::vector<uint64_t> item, 
    uint32_t kappa
) {
    std::vector<uint64_t> ret(kappa);
    uint64_t maskLen = 64 / kappa;
    uint64_t masking = ((uint64_t)(1) << maskLen) - 1;
    uint32_t subKappa = kappa / item.size();
    
    for (uint32_t i = 0; i < item.size(); i++) {
        uint64_t curr_item = item[i];
        uint32_t offset = i * subKappa;
        for (uint32_t j = 0; j < subKappa; j++) {
            ret[offset + j] = curr_item & masking;
            curr_item >>= maskLen;
        }
    }
    return ret;
}



// Dataset Generation
// Assume Label Values are already pre-processed
EncryptedDB constructDB(
    CryptoContext<DCRTPoly> cc,
    PublicKey<DCRTPoly> pk,
    std::vector<std::vector<uint64_t>> idMsgVec,
    std::vector<double> labMsgVec,
    double statVal,
    uint32_t kappa
) {
    // 
    uint32_t numItems = idMsgVec.size();
    // Pre-process the idMsgVec
    std::vector<std::vector<uint64_t>> chunkedDB(numItems);

    #pragma omp parallel for num_threads(MAX_NUM_CORES)
    for (uint32_t i = 0; i < numItems; i++) {
        chunkedDB[i] = chunkDataset(idMsgVec[i], kappa);
    }

    // Encrypt the database and label
    // We will manage the database by each "chunks"
    uint32_t chunkSize = (1<<16) / kappa;
    uint32_t numChunk = numItems / chunkSize + (numItems % chunkSize != 0);

    // Prepare Statistics
    std::vector<double> statVec(1<<16, 0.0);
    for (uint32_t i = 0; i < chunkSize; i++) {
        statVec[i * kappa] = statVal;
    }
    Plaintext ptxtStat = cc->MakeCKKSPackedPlaintext(statVec);
    Ciphertext<DCRTPoly> stat = cc->Encrypt(ptxtStat, pk);


    std::vector<EncryptedChunk> chunks(numChunk);

    #pragma omp parallel for num_threads(MAX_NUM_CORES)
    for (uint32_t i = 0; i < numChunk; i++) {
        uint32_t offset = chunkSize * i;

        // Read Database
        std::vector<double> _tmpIdVec(1<<16, 0.0);
        std::vector<double> _tmpLabVec(1<<16, 0.0);
        for (uint32_t j = 0; j < chunkSize; j++) {
            _tmpLabVec[j * kappa] = labMsgVec[offset + j];
            for (uint32_t k = 0; k < kappa; k++) {
                if (offset + j >= numItems) {
                    // Dummy Value
                    _tmpIdVec[j * kappa + k] = -1;
                } else {
                    _tmpIdVec[j * kappa + k] = chunkedDB[offset + j][k];                
                }                
            }
        }

        // Encrypt Data
        Plaintext ptxtId = cc->MakeCKKSPackedPlaintext(_tmpIdVec);
        Plaintext ptxtLab = cc->MakeCKKSPackedPlaintext(_tmpLabVec);
        chunks[i] = EncryptedChunk {
            cc->Encrypt(ptxtId, pk),
            cc->Encrypt(ptxtLab, pk),
            stat,
            kappa
        };
    }

    // Done!
    return EncryptedDB {
        chunks, stat, kappa
    };
}


// Horizontal Database
EncryptedHorizontalDB constructHorizontalDB(
    CryptoContext<DCRTPoly> cc,
    PublicKey<DCRTPoly> pk,
    std::vector<std::vector<uint64_t>> idMsgVec,
    std::vector<std::vector<double>> labMsgVec,
    double statVal,
    uint32_t kappa
) {
    // 
    uint32_t numItems = idMsgVec.size();
    // Pre-process the idMsgVec
    std::vector<std::vector<uint64_t>> chunkedDB(numItems);

    #pragma omp parallel for num_threads(MAX_NUM_CORES)
    for (uint32_t i = 0; i < numItems; i++) {
        chunkedDB[i] = chunkDataset(idMsgVec[i], kappa);
    }

    // Encrypt the database and label
    // We will manage the database by each "chunks"
    uint32_t chunkSize = (1<<16) / kappa;
    uint32_t numChunk = numItems / chunkSize + (numItems % chunkSize != 0);

    // Label Chunking
    uint32_t numLabels = labMsgVec.size();
    uint32_t numLabelChunk = numLabels / kappa + (numLabels % kappa != 0);

    // Prepare Statistics
    std::vector<double> statVec(1<<16, 0.0);
    for (uint32_t i = 0; i < chunkSize; i++) {
        statVec[i * kappa] = statVal;
    }
    Plaintext ptxtStat = cc->MakeCKKSPackedPlaintext(statVec);
    Ciphertext<DCRTPoly> stat = cc->Encrypt(ptxtStat, pk);


    std::vector<EncryptedHorizontalChunk> chunks(numChunk);

    #pragma omp parallel for num_threads(MAX_NUM_CORES)
    for (uint32_t i = 0; i < numChunk; i++) {
        uint32_t offset = chunkSize * i;

        // Read Database
        std::vector<double> _tmpIdVec(1<<16, 0.0);
        for (uint32_t j = 0; j < chunkSize; j++) {
            

            // Encoding of IDVecs
            for (uint32_t k = 0; k < kappa; k++) {
                if (offset + j >= numItems) {
                    // Dummy Value
                    _tmpIdVec[j * kappa + k] = -1;
                } else {
                    _tmpIdVec[j * kappa + k] = chunkedDB[offset + j][k];                
                }                
            }
        }
        Plaintext ptxtID = cc->MakeCKKSPackedPlaintext(_tmpIdVec);
        Ciphertext<DCRTPoly> idCtxt = cc->Encrypt(ptxtID, pk);

        // Label Encoding
        // TODO: Optimization
        Plaintext ptxtLab;
        std::vector<Ciphertext<DCRTPoly>> labelCtxt(numLabelChunk);
        for (uint32_t j = 0; j < numLabelChunk; j++) {
            std::vector<double> _tmpLabVec(1<<16, 0);
            uint32_t labOffset = j * kappa;
            for (uint32_t k = 0; k < chunkSize; k++) {
                for (uint32_t l = 0; l < kappa; l++) {
                    // Dummy Value
                    if (j * kappa + l >= labOffset) {
                        _tmpLabVec[k * kappa + l] = 0;
                    } else {
                        _tmpLabVec[k * kappa + l] = labMsgVec[j * kappa + l][offset + k];
                    }
                }
            }
            ptxtLab = cc->MakeCKKSPackedPlaintext(_tmpLabVec);
            labelCtxt[j] = cc->Encrypt(ptxtLab, pk);
        }


        // Encrypt Data        
        chunks[i] = EncryptedHorizontalChunk {
            idCtxt,
            labelCtxt,
            stat,
            kappa
        };
    }

    // Done!
    return EncryptedHorizontalDB {
        chunks, stat, kappa
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

// Computing Intersection for Chunks
Ciphertext<DCRTPoly> compInterChunks (
    CryptoContext<DCRTPoly> cc,
    VAFParams params,
    std::vector<EncryptedChunk> chunks,
    Ciphertext<DCRTPoly> queryCtxt
) {

    uint32_t numChunks = chunks.size();
    uint32_t kappa = chunks[0].kappa;

    // Step 1. Evaluate VAF
    std::vector<Ciphertext<DCRTPoly>> vafResultVec(numChunks);
    std::vector<Ciphertext<DCRTPoly>> labResultVec(numChunks);

    // Masking Vector
    std::vector<double> _tmpVec(1<<16, 0.0);
    for (uint32_t i = 0;  i < (1<<16); i += chunks[0].kappa) {
        _tmpVec[i] = 1;
    }
    Plaintext maskPtxt = cc->MakeCKKSPackedPlaintext(_tmpVec);

    std::cout << "\nNumChunks: " << numChunks << std::endl;

    if (numChunks > 2) {

        std::cout << "\nW/ multi-threading (T=" << MAX_NUM_CORES << ")... " << std::endl;
        #pragma omp parallel for num_threads(MAX_NUM_CORES)
        for (uint32_t i = 0; i < numChunks; i++) {
        vafResultVec[i] = cc->EvalSub(chunks[i].idCtxt, queryCtxt);
        // Evaluate VAF HERE
        vafResultVec[i] = fusedVAFfromParams(cc, vafResultVec[i], params);

        // Rotation & Multiplication
        vafResultVec[i] = preserveSlotZero(cc, vafResultVec[i], kappa);

        // Final Masking
        vafResultVec[i] = cc->EvalMult(vafResultVec[i], maskPtxt);

        // Label Embedding

        labResultVec[i] = cc->EvalMult(vafResultVec[i], chunks[i].labelCtxt);
        }
    }
    else {
        std::cout << "\nW/0 multi-threading... " << std::endl;
        for (uint32_t i = 0; i < numChunks; i++) {
        vafResultVec[i] = cc->EvalSub(chunks[i].idCtxt, queryCtxt);
        // Evaluate VAF HERE
        vafResultVec[i] = fusedVAFfromParams(cc, vafResultVec[i], params);

        // Rotation & Multiplication
        vafResultVec[i] = preserveSlotZero(cc, vafResultVec[i], kappa);

        // Final Masking
        vafResultVec[i] = cc->EvalMult(vafResultVec[i], maskPtxt);

        // Label Embedding
        labResultVec[i] = cc->EvalMult(vafResultVec[i], chunks[i].labelCtxt);
        }
    }
    
    // Additive Aggregation
    Ciphertext<DCRTPoly> vafResult = cc->EvalAddMany(vafResultVec);
    Ciphertext<DCRTPoly> labResult = cc->EvalAddMany(labResultVec);

    // std::cout << DB.kappa << std::endl;
    // std::cout << "YAY!" << std::endl;

    // Rotation & Addition
    Ciphertext<DCRTPoly> _tmp;
    for (uint32_t i = kappa; i < 65536; i = i * 2) {
        _tmp = cc->EvalRotate(vafResult, i);
        vafResult = cc->EvalAdd(vafResult, _tmp);
        _tmp = cc->EvalRotate(labResult, i);
        labResult = cc->EvalAdd(labResult, _tmp);
        // std::cout << "YAY!" << std::endl;
    }

    // Choice Statistics
    Ciphertext<DCRTPoly> ret = labResult->Clone();
    _tmp = cc->EvalSub(1.0, vafResult);
    _tmp = cc->EvalMult(_tmp, chunks[0].stat);
    cc->EvalAddInPlace(ret, _tmp);
    _tmp = cc->EvalRotate(vafResult, -1);
    cc->EvalAddInPlace(ret, _tmp);

    // Done!
    return ret;    
}

// A protocol returning Compact Representation
Ciphertext<DCRTPoly> compInterCompactChunks(
    CryptoContext<DCRTPoly> cc,
    VAFParams params,
    std::vector<EncryptedChunk> chunks,
    Ciphertext<DCRTPoly> queryCtxt,
    uint32_t serverIdx,
    uint32_t rotRange
) {
    uint32_t numChunks = chunks.size();
    uint32_t kappa = chunks[0].kappa;

    // Step 1. Evaluate VAF
    std::vector<Ciphertext<DCRTPoly>> vafResultVec(numChunks);
    std::vector<Ciphertext<DCRTPoly>> labResultVec(numChunks);

    // Masking Vector
    std::vector<double> _tmpVec(1<<16, 0.0);
    for (uint32_t i = 0;  i < (1<<16); i += kappa) {
        _tmpVec[i] = 1;
    }
    Plaintext maskPtxt = cc->MakeCKKSPackedPlaintext(_tmpVec);
    // std::cout << DB.idVec.size() << std::endl;

    std::cout << "\nNumChunks: " << numChunks << std::endl;

    if (numChunks > 2) {

        std::cout << "\nW/ multi-threading (T=" << MAX_NUM_CORES << ")... " << std::endl;
        #pragma omp parallel for num_threads(MAX_NUM_CORES)
        for (uint32_t i = 0; i < numChunks; i++) {
        vafResultVec[i] = cc->EvalSub(chunks[i].idCtxt, queryCtxt);
        // Evaluate VAF HERE
        vafResultVec[i] = fusedVAFfromParams(cc, vafResultVec[i], params);

        // Rotation & Multiplication
        vafResultVec[i] = preserveSlotZero(cc, vafResultVec[i], kappa);

        // Final Masking
        vafResultVec[i] = cc->EvalMult(vafResultVec[i], maskPtxt);

        // Label Embedding
        labResultVec[i] = cc->EvalMult(vafResultVec[i], chunks[i].labelCtxt);
        }
    }
    else {
        std::cout << "\nW/0 multi-threading... " << std::endl;
        for (uint32_t i = 0; i < numChunks; i++) {
        vafResultVec[i] = cc->EvalSub(chunks[i].idCtxt, queryCtxt);
        // Evaluate VAF HERE
        vafResultVec[i] = fusedVAFfromParams(cc, vafResultVec[i], params);

        // Rotation & Multiplication
        vafResultVec[i] = preserveSlotZero(cc, vafResultVec[i], kappa);

        // Final Masking
        vafResultVec[i] = cc->EvalMult(vafResultVec[i], maskPtxt);

        // Label Embedding
        labResultVec[i] = cc->EvalMult(vafResultVec[i], chunks[i].labelCtxt);
        }
    }
    
    // Additive Aggregation
    Ciphertext<DCRTPoly> vafResult = cc->EvalAddMany(vafResultVec);
    Ciphertext<DCRTPoly> labResult = cc->EvalAddMany(labResultVec);

    // Rotation & Addition
    Ciphertext<DCRTPoly> _tmp;
    for (uint32_t i = 1; i < 65536; i = i * 2) {
        _tmp = cc->EvalRotate(vafResult, i);
        vafResult = cc->EvalAdd(vafResult, _tmp);
        _tmp = cc->EvalRotate(labResult, i);
        labResult = cc->EvalAdd(labResult, _tmp);
    }

    // Choice Statistics
    Ciphertext<DCRTPoly> ret = labResult->Clone();
    _tmp = cc->EvalSub(1.0, vafResult);
    _tmp = cc->EvalMult(_tmp, chunks[0].stat);
    cc->EvalAddInPlace(ret, _tmp);

    // Extraction
    std::vector<double> _maskFinalLab(1<<16, 0); _maskFinalLab[serverIdx] = 1;
    std::vector<double> _maskFinalID(1<<16, 0); _maskFinalID[rotRange] = 1;
    Plaintext _ptxt = cc->MakeCKKSPackedPlaintext(_maskFinalLab);
    ret = cc->EvalMult(ret, _ptxt);
    _ptxt = cc->MakeCKKSPackedPlaintext(_maskFinalID);
    _tmp = cc->EvalMult(vafResult, _ptxt);
    cc->EvalAddInPlace(ret, _tmp);
    return ret;
}

// Horizontal Chunks
// Only Supports for Compact Representation
Ciphertext<DCRTPoly> compInterCompactHorizontalChunks(
    CryptoContext<DCRTPoly> cc,
    VAFParams params,
    std::vector<EncryptedHorizontalChunk> chunks,
    Ciphertext<DCRTPoly> queryCtxt,
    uint32_t serverIdx,
    uint32_t rotRange
) {
    uint32_t numChunks = chunks.size();
    uint32_t kappa = chunks[0].kappa;
    uint32_t numLabelChunks = chunks[0].labelCtxt.size();

    // Step 1. Evaluate VAF
    std::vector<Ciphertext<DCRTPoly>> vafResultVec(numChunks);
    std::vector<std::vector<Ciphertext<DCRTPoly>>> labResultVec(numLabelChunks);

    for (uint32_t i = 0; i < numLabelChunks; i++) {
        std::vector<Ciphertext<DCRTPoly>> _tmp(numChunks);
        labResultVec[i] = _tmp;
    }

    // Masking Vector
    std::vector<double> _tmpVec(1<<16, 0.0);
    for (uint32_t i = 0;  i < (1<<16); i += kappa) {
        _tmpVec[i] = 1;
    }
    Plaintext maskPtxt = cc->MakeCKKSPackedPlaintext(_tmpVec);
    // std::cout << DB.idVec.size() << std::endl;

    #pragma omp parallel for num_threads(MAX_NUM_CORES)
    for (uint32_t i = 0; i < numChunks; i++) {
        vafResultVec[i] = cc->EvalSub(chunks[i].idCtxt, queryCtxt);
        // Evaluate VAF HERE
        vafResultVec[i] = fusedVAFfromParams(cc, vafResultVec[i], params);

        // Rotation & Multiplication
        vafResultVec[i] = preserveSlotZero(cc, vafResultVec[i], kappa);

        // Final Masking
        vafResultVec[i] = cc->EvalMult(vafResultVec[i], maskPtxt);

        // Prepare for Label Extraction
        Ciphertext<DCRTPoly> _tmp;
        for (uint32_t j = 1; j < kappa; j *= 2) {
            _tmp = cc->EvalRotate(vafResultVec[i], -j);
            vafResultVec[i] = cc->EvalAdd(vafResultVec[i], _tmp);
        }

        // Do Label Extraction
        for (uint32_t j = 0; j < numLabelChunks; j++) {
            labResultVec[j][i] = cc->EvalMult(vafResultVec[i], chunks[i].labelCtxt[j]);
        }
    }
    // Additive Aggregation
    Ciphertext<DCRTPoly> vafResult = cc->EvalAddMany(vafResultVec);

    // Rotation & Addition
    Ciphertext<DCRTPoly> _tmp;
    for (uint32_t i = kappa; i < 65536; i = i * 2) {
        _tmp = cc->EvalRotate(vafResult, i);
        vafResult = cc->EvalAdd(vafResult, _tmp);
    }


    std::vector<Ciphertext<DCRTPoly>> labResults(numLabelChunks);

    // TODO: Do Parallelization...?
    for (uint32_t i = 0; i < numLabelChunks; i++) {
        labResults[i] = cc->EvalAddMany(labResultVec[i]);

        for (uint32_t j = kappa; j < 65536; j *= 2) {
            _tmp = cc->EvalRotate(labResults[i], j);
            labResults[i] = cc->EvalAdd(labResults[i], _tmp);    
        }        

        // Choice Statistics
        Ciphertext<DCRTPoly> ret = labResults[i]->Clone();
        _tmp = cc->EvalSub(1.0, vafResult);
        _tmp = cc->EvalMult(_tmp, chunks[0].stat);
        cc->EvalAddInPlace(ret, _tmp);   
        
        std::vector<double> _maskFinalLab(1<<16, 0); 
        uint32_t offset = i * kappa;
        for (uint32_t j = 0; j < kappa; j++) {
            _maskFinalLab[offset + j] = 1;
        }
        Plaintext _ptxt = cc->MakeCKKSPackedPlaintext(_maskFinalLab);
        labResults[i] = cc->EvalMult(labResults[i], _ptxt);
    }

    std::vector<double> _maskFinalID(1<<16, 0); _maskFinalID[rotRange] = 1;
    Ciphertext<DCRTPoly> ret = cc->EvalAddMany(labResults);
    Plaintext _ptxt = cc->MakeCKKSPackedPlaintext(_maskFinalID);
    _tmp = cc->EvalMult(vafResult, _ptxt);
    cc->EvalAddInPlace(ret, _tmp);
    return ret;
}



// Do Intersection
Ciphertext<DCRTPoly> compInterDB(
    CryptoContext<DCRTPoly> cc,
    VAFParams params,
    EncryptedDB DB,
    Ciphertext<DCRTPoly> queryCtxt
) {
    // Just run the intersection over all chunks
    return compInterChunks(cc, params, DB.chunks, queryCtxt);
}

// A protocol returning Compact Representation
Ciphertext<DCRTPoly> compInterCompactDB(
    CryptoContext<DCRTPoly> cc,
    VAFParams params,
    EncryptedDB DB,
    Ciphertext<DCRTPoly> queryCtxt,
    uint32_t serverIdx,
    uint32_t rotRange
) {
    // Just run the intersection over all chunks
    return compInterCompactChunks(cc, params, DB.chunks, queryCtxt, serverIdx, rotRange);
}

// A protocol returning Compact Representation
Ciphertext<DCRTPoly> compInterCompactHorizontalDB(
    CryptoContext<DCRTPoly> cc,
    VAFParams params,
    EncryptedHorizontalDB DB,
    Ciphertext<DCRTPoly> queryCtxt,
    uint32_t serverIdx,
    uint32_t rotRange
) {
    // Just run the intersection over all chunks
    return compInterCompactHorizontalChunks(cc, params, DB.chunks, queryCtxt, serverIdx, rotRange);
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

    // Do Rescale Before Return
    uint32_t lvlevalRet = evalRet->GetLevel();
    uint32_t lvlisInter = isInter->GetLevel();

    if (lvlisInter > lvlevalRet) {
        uint32_t numRS = lvlisInter - lvlevalRet;
        for (uint32_t i = 0; i < numRS; i++) {
            cc->Rescale(evalRet);
        }
    } else {
        uint32_t numRS = lvlevalRet - lvlisInter;
        for (uint32_t i = 0; i < numRS; i++) {
            cc->Rescale(isInter);
        }        
    }

    return LSResponse { evalRet, isInter };
}

// Operation with the server with a compact representation.
LSResponse evalCircuitCompact(
    CryptoContext<DCRTPoly> cc,
    std::vector<Ciphertext<DCRTPoly>> ctxts,
    VAFParams paramsVAF,
    LogRegParamsCompact paramsLR,
    uint32_t kappa
) {
    // Summates all the ciphertexts
    auto evalRet = cc->EvalAddMany(ctxts);

    // Extract Membership information
    std::vector<double> _maskVec(1<<16, 0); _maskVec[paramsLR.rotRange] = 1;
    Plaintext _ptxt = cc->MakeCKKSPackedPlaintext(_maskVec);
    auto isInter = cc->EvalMult(evalRet, _ptxt);
    cc->EvalSubInPlace(evalRet, isInter);

    // Evaluate Logistic Regression
    evalRet = logRegEvalCompact(cc, paramsLR, evalRet);
    std::vector<double> _maskVecRet(1<<16, 0); _maskVecRet[0] = 1;

    Plaintext maskPtxtRet = cc->MakeCKKSPackedPlaintext(_maskVecRet);
    evalRet = cc->EvalMult(evalRet, maskPtxtRet);

    // Do a VAF evaluation
    isInter = fusedVAFfromParams(cc, isInter, paramsVAF);
    isInter = cc->EvalSub(1.0, isInter);
    
    // Do Rescale Before Return
    uint32_t lvlevalRet = evalRet->GetLevel();
    uint32_t lvlisInter = isInter->GetLevel();

    if (lvlisInter > lvlevalRet) {
        uint32_t numRS = lvlisInter - lvlevalRet;
        for (uint32_t i = 0; i < numRS; i++) {
            cc->Rescale(evalRet);
        }
    } else {
        uint32_t numRS = lvlevalRet - lvlisInter;
        for (uint32_t i = 0; i < numRS; i++) {
            cc->Rescale(isInter);
        }        
    }    

    return LSResponse { evalRet, isInter };
}

// Evalauting Circuit for Chunks
LSResponse evalCircuitfromChunks(
    CryptoContext<DCRTPoly> cc,
    std::vector<std::vector<Ciphertext<DCRTPoly>>> ctxtVecs,
    VAFParams paramsVAF,
    LogRegParams paramsLR,
    uint32_t kappa
) {
    // Prepare the ctxts
    uint32_t numLabels = ctxtVecs.size();
    std::vector<Ciphertext<DCRTPoly>> ctxts(numLabels);

    #pragma omp parallel for num_threads(MAX_NUM_CORES)
    for (uint32_t i = 0; i < numLabels; i++) {
        ctxts[i] = cc->EvalAddMany(ctxtVecs[i]);
    }

    // Do the original code
    return evalCircuit(cc, ctxts, paramsVAF, paramsLR, kappa);
}

// Evalauting Circuit for Chunks
LSResponse evalCircuitCompactfromChunks(
    CryptoContext<DCRTPoly> cc,
    std::vector<std::vector<Ciphertext<DCRTPoly>>> ctxtVecs,
    VAFParams paramsVAF,
    LogRegParamsCompact paramsLR,
    uint32_t kappa
) {
    // Prepare the ctxts
    uint32_t numLabels = ctxtVecs.size();
    std::vector<Ciphertext<DCRTPoly>> ctxts(numLabels);

    #pragma omp parallel for num_threads(MAX_NUM_CORES)
    for (uint32_t i = 0; i < numLabels; i++) {
        ctxts[i] = cc->EvalAddMany(ctxtVecs[i]);
    }

    // Do the original code
    return evalCircuitCompact(cc, ctxts, paramsVAF, paramsLR, kappa);
}

