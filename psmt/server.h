#ifndef SERVER_H
#define SERVER_H

#include "openfhe.h"
#include "../logreg/core.h"
#include "../include/core.h"

using namespace lbcrypto;

typedef struct _EncryptedDB {
    std::vector<Ciphertext<DCRTPoly>> idVec;
    std::vector<Ciphertext<DCRTPoly>> labelVec;
    Ciphertext<DCRTPoly> stat;
    uint32_t kappa; 
} EncryptedDB;

typedef struct _LSResponse {
    Ciphertext<DCRTPoly> evalRet;
    Ciphertext<DCRTPoly> isInter;
} LSResponse;

EncryptedDB constructDB(
    CryptoContext<DCRTPoly> cc,
    PublicKey<DCRTPoly> pk,
    std::vector<uint64_t> idMsgVec,
    std::vector<double> labMsgVec,
    double statVal,
    uint32_t kappa
);
 
Ciphertext<DCRTPoly> preserveSlotZero(
    CryptoContext<DCRTPoly> cc,
    Ciphertext<DCRTPoly> ct,              // ciphertext with kappa number of chunks -> kappa must be a power of two    
    size_t kappa                            
);

Ciphertext<DCRTPoly> compInter(
    CryptoContext<DCRTPoly> cc,
    VAFParams params,
    EncryptedDB DB,
    Ciphertext<DCRTPoly> queryCtxt
);

Ciphertext<DCRTPoly> compInterCompact(
    CryptoContext<DCRTPoly> cc,
    VAFParams params,
    EncryptedDB DB,
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

LSResponse evalCircuitCompact(
    CryptoContext<DCRTPoly> cc,
    std::vector<Ciphertext<DCRTPoly>> ctxts,
    VAFParams paramsVAF,
    LogRegParamsCompact paramsLR,
    uint32_t kappa
);



#endif