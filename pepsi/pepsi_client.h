#ifndef PEPSI_CLIENT_H
#define PEPSI_CLIENT_H

#include <openfhe.h>

using namespace lbcrypto;

typedef struct _PEPSIQuery {
    std::vector<Ciphertext<DCRTPoly>> payload;
    uint32_t numCtxt;
    uint32_t kVal;
} PEPSIQuery;

PEPSIQuery encryptClientData (
    CryptoContext<DCRTPoly> cc,
    PublicKey<DCRTPoly> pk,
    uint64_t data,
    uint32_t numCtxt,
    uint32_t kVal
);

bool checkIntResult (
    CryptoContext<DCRTPoly> cc,
    PrivateKey<DCRTPoly> sk,
    Ciphertext<DCRTPoly> resCtxt
);

#endif