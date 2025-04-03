#ifndef PEPSI_CORE_H
#define PEPSI_CORE_H

#include <openfhe.h>

#define NUM_RAND_MASKS 16

using namespace lbcrypto;

std::vector<std::vector<uint64_t>> chooseTable(uint64_t n);

std::vector<int64_t> getCW(
    uint64_t data,
    uint32_t numCtxt,
    uint32_t kVal
);


Ciphertext<DCRTPoly> arithCWEQ(
    CryptoContext<DCRTPoly> cc,
    std::vector<Ciphertext<DCRTPoly>> ctxt1,
    // std::vector<Plaintext> ctxt2,
    std::vector<Ciphertext<DCRTPoly>> ctxt2,
    Plaintext ptDiv,
    uint32_t kVal
);

Ciphertext<DCRTPoly> arithCWEQPtxt(
    CryptoContext<DCRTPoly> cc,
    std::vector<Ciphertext<DCRTPoly>> ctxt,
    std::vector<Plaintext> ptxt,
    Plaintext ptDiv,
    uint32_t kVal
);

std::vector<int64_t> getCWTable(
    uint64_t data,
    uint32_t numCtxt,
    uint32_t kVal,
    std::vector<std::vector<uint64_t>> table
);

Ciphertext<DCRTPoly> genRandCiphertext(
    CryptoContext<DCRTPoly> cc,
    PublicKey<DCRTPoly> pk,
    uint32_t numRand
);

Ciphertext<DCRTPoly> sumOverSlots(
    CryptoContext<DCRTPoly> cc,
    Ciphertext<DCRTPoly> ctxt
);

#endif