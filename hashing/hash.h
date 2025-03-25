#ifndef HASH_H
#define HASH_H

#include <stdint.h>
#include <vector>
#include <openssl/sha.h>
#include <stdexcept>
#include <algorithm>

#include "openfhe.h"

using namespace lbcrypto;

uint64_t computeHash(
    std::vector<uint64_t> input, uint32_t salt = 42
);

std::vector<uint64_t> chunkData64(
    uint64_t item,
    uint32_t kappa // # of chunks
);

std::vector<std::vector<double>> computeHashTable(
    std::vector<uint64_t> inputVec,
    uint32_t ringDim,
    uint32_t kappa,
    uint32_t maxBinItems,
    double dummyVal = 30
);

std::vector<Ciphertext<DCRTPoly>> encryptTable(
    CryptoContext<DCRTPoly> cc,
    PublicKey<DCRTPoly> pk,
    std::vector<std::vector<double>> hashTable,
    uint32_t ringDim,
    uint32_t maxBinItems
);

#endif