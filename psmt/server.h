#ifndef SERVER_H
#define SERVER_H

#include "openfhe.h"
#include "../logreg/core.h"
#include "../include/core.h"
#include "utils.h"

using namespace lbcrypto;

typedef struct _EncryptedHorizontalChunk {
    Ciphertext<DCRTPoly> idCtxt;
    std::vector<Ciphertext<DCRTPoly>> labelCtxt;
    Ciphertext<DCRTPoly> stat;
    uint32_t kappa;
} EncryptedHorizontalChunk;

typedef struct _EncryptedChunk {
    Ciphertext<DCRTPoly> idCtxt;
    Ciphertext<DCRTPoly> labelCtxt;
    Ciphertext<DCRTPoly> stat;
    uint32_t kappa;
} EncryptedChunk;

typedef struct _EncryptedHorizontalDB {
    std::vector<EncryptedHorizontalChunk> chunks;
    Ciphertext<DCRTPoly> stat;
    uint32_t kappa; 
} EncryptedHorizontalDB;

typedef struct _EncryptedDB {
    std::vector<EncryptedChunk> chunks;
    Ciphertext<DCRTPoly> stat;
    uint32_t kappa; 
} EncryptedDB;

typedef struct _LSResponse {
    Ciphertext<DCRTPoly> evalRet;
    Ciphertext<DCRTPoly> isInter;
} LSResponse;

EncryptedHorizontalDB constructHorizontalDB(
    CryptoContext<DCRTPoly> cc,
    PublicKey<DCRTPoly> pk,
    std::vector<std::vector<uint64_t>> idMsgVec,
    std::vector<std::vector<double>> labMsgVec,
    double statVal,
    uint32_t kappa
);

EncryptedDB constructDB(
    CryptoContext<DCRTPoly> cc,
    PublicKey<DCRTPoly> pk,
    std::vector<std::vector<uint64_t>> idMsgVec,
    std::vector<double> labMsgVec,
    double statVal,
    uint32_t kappa
);
 
Ciphertext<DCRTPoly> preserveSlotZero(
    CryptoContext<DCRTPoly> cc,
    Ciphertext<DCRTPoly> ct,              // ciphertext with kappa number of chunks -> kappa must be a power of two    
    size_t kappa                            
);

Ciphertext<DCRTPoly> compInterChunks (
    CryptoContext<DCRTPoly> cc,
    VAFParams params,
    std::vector<EncryptedChunk> chunks,
    Ciphertext<DCRTPoly> queryCtxt
);

Ciphertext<DCRTPoly> compInterCompactChunks(
    CryptoContext<DCRTPoly> cc,
    VAFParams params,
    std::vector<EncryptedChunk> chunks,
    Ciphertext<DCRTPoly> queryCtxt,
    uint32_t serverIdx,
    uint32_t rotRange
);

Ciphertext<DCRTPoly> compInterCompactHorizontalChunks(
    CryptoContext<DCRTPoly> cc,
    VAFParams params,
    std::vector<EncryptedHorizontalChunk> chunks,
    Ciphertext<DCRTPoly> queryCtxt,
    uint32_t serverIdx,
    uint32_t rotRange
);


Ciphertext<DCRTPoly> compInterDB(
    CryptoContext<DCRTPoly> cc,
    VAFParams params,
    EncryptedDB DB,
    Ciphertext<DCRTPoly> queryCtxt
);

Ciphertext<DCRTPoly> compInterCompactDB(
    CryptoContext<DCRTPoly> cc,
    VAFParams params,
    EncryptedDB DB,
    Ciphertext<DCRTPoly> queryCtxt,
    uint32_t serverIdx,
    uint32_t rotRange
);

Ciphertext<DCRTPoly> compInterCompactHorizontalDB(
    CryptoContext<DCRTPoly> cc,
    VAFParams params,
    EncryptedHorizontalDB DB,
    Ciphertext<DCRTPoly> queryCtxt,
    uint32_t serverIdx,
    uint32_t rotRange
);


LSResponse evalCircuit(
    CryptoContext<DCRTPoly> cc,
    std::vector<Ciphertext<DCRTPoly>> ctxts,
    VAFParams paramsVAF,
    LogRegParams paramsLR,
    uint32_t kappa
);

LSResponse evalCircuitfromChunks(
    CryptoContext<DCRTPoly> cc,
    std::vector<std::vector<Ciphertext<DCRTPoly>>> ctxtVecs,
    VAFParams paramsVAF,
    LogRegParams paramsLR,
    uint32_t kappa
);

LSResponse evalCircuitCompact(
    CryptoContext<DCRTPoly> cc,
    std::vector<Ciphertext<DCRTPoly>> ctxts,
    VAFParams paramsVAF,
    LogRegParamsCompact paramsLR,
    uint32_t kappa
);

LSResponse evalCircuitCompactfromChunks(
    CryptoContext<DCRTPoly> cc,
    std::vector<std::vector<Ciphertext<DCRTPoly>>> ctxtVecs,
    VAFParams paramsVAF,
    LogRegParamsCompact paramsLR,
    uint32_t kappa
);

#endif
