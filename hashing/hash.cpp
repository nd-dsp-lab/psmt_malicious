#include "hash.h"

#include <openssl/evp.h>  // Use EVP interface instead of direct SHA256 functions
#include <openssl/sha.h>
#include <vector>
#include <cstdint>

uint64_t computeHash(std::vector<uint64_t> input, uint32_t salt) {
    unsigned char hash[SHA256_DIGEST_LENGTH] = {0};

    // Use EVP (Recommended for OpenSSL 3.x)
    EVP_MD_CTX* sha256 = EVP_MD_CTX_new();
    EVP_DigestInit_ex(sha256, EVP_sha256(), nullptr);
    EVP_DigestUpdate(sha256, &salt, sizeof(salt));

    for (uint64_t num : input) {
        EVP_DigestUpdate(sha256, &num, sizeof(num));
    }

    EVP_DigestFinal_ex(sha256, hash, nullptr);
    EVP_MD_CTX_free(sha256);  // Free the context

    uint64_t* result_ptr = reinterpret_cast<uint64_t*>(hash);
    return *result_ptr;
}

// Chunking Technique
// For 64-bit Items
std::vector<uint64_t> chunkData64(
    uint64_t item,
    uint32_t kappa // # of chunks
) {
    std::vector<uint64_t> retVec(kappa, 0); 
    uint64_t moveSize = 64 / kappa;
    uint64_t mask = ((uint64_t)(1) << moveSize) - 1; 

    for (uint32_t i = 0; i < kappa; i++) {
        retVec[kappa - i - 1] = item & mask;
        item >>= moveSize;
    }
    return retVec;
}

// Construct a Hash Table for Vector-Valued Items
std::vector<std::vector<double>> computeHashTable(
    std::vector<uint64_t> inputVec,
    uint32_t ringDim,
    uint32_t kappa,
    uint32_t maxBinItems,
    double dummyVal
) {
    // Chunking
    std::vector<std::vector<uint64_t>> chunkedInputVec(inputVec.size());

    #pragma omp parallel for
    for (uint32_t i = 0; i < inputVec.size(); i++) {
        chunkedInputVec[i] = chunkData64(inputVec[i], kappa);
    }

    // Initialize Hash Table
    uint32_t numBins = ringDim / kappa;
    std::vector<std::vector<double>> retTable(ringDim);
    std::vector<uint32_t> currItems(ringDim, 0);

    for (auto& innerVec: retTable) {
        innerVec.resize(maxBinItems, dummyVal);
    }        

    #pragma omp parallel for
    for (uint32_t i = 0; i < inputVec.size(); i++) {
        uint64_t ret = computeHash(chunkedInputVec[i], 42) % numBins;
        for (uint32_t j = 0; j < kappa; j++) {
            uint32_t idx = numBins * j + ret;
            retTable[idx][currItems[idx]] =  (double)chunkedInputVec[i][j];
            currItems[idx] += 1;
        }
    }

    std::cout << "MAX Items: " << *std::max_element(currItems.begin(), currItems.end()) << std::endl;

    return retTable;
}

// Encrypt a hash table
std::vector<Ciphertext<DCRTPoly>> encryptTable(
    CryptoContext<DCRTPoly> cc,
    PublicKey<DCRTPoly> pk,
    std::vector<std::vector<double>> hashTable,
    uint32_t ringDim,
    uint32_t maxBinItems
) {
    std::vector<Ciphertext<DCRTPoly>> retCtxts(maxBinItems);

    #pragma omp parallel for
    for (uint32_t i = 0; i < maxBinItems; i++) {
        std::vector<double> _tmpVec(ringDim);

        for (uint32_t j = 0; j < ringDim; j++) {
            _tmpVec[j] = hashTable[j][i];
        }
        auto ptxt = cc->MakeCKKSPackedPlaintext(_tmpVec);
        retCtxts[i] = cc->Encrypt(ptxt, pk);
    }
    return retCtxts;
}