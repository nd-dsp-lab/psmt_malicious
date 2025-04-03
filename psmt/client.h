#ifndef PSMT_CLIENT_H
#define PSMT_CLIENT_H

#include "openfhe.h"
using namespace lbcrypto;

Ciphertext<DCRTPoly> encryptQuery(
    CryptoContext<DCRTPoly> cc,
    PublicKey<DCRTPoly> pk,
    std::vector<uint64_t> item,
    uint32_t kappa
);


#endif