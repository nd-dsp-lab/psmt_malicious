#include "tests.h"
#include "hash.h"
#include "../include/fhe_init.h"

std::vector<uint64_t> genData(
    uint32_t numItems
) {
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<uint64_t> dist(1, (uint64_t)(1)<<63);

    std::vector<uint64_t> retVec(numItems);

    #pragma omp parallel for
    for (uint32_t i = 0; i < numItems; i++) {
        retVec[i] = dist(gen);
    }
    return retVec;
}


void testHashing() {
    // Construct Cryptographic Parameters!
    std::cout << "<<< " << "HASHING TEST" << ">>>" << std::endl;
    FHEParams params;
    params.multiplicativeDepth = 10;
    params.ringDim = 1<<17;
    params.scalingModSize = 35;
    params.firstModSize = 59;

    FHEContext ctx = InitFHE(params);
    auto cc = ctx.cryptoContext; 
    auto pk = ctx.keyPair.publicKey;
    auto sk = ctx.keyPair.secretKey;

    // Setup the database
    std::vector<uint64_t> dataVec = genData(1<<20);

    std::cout << "START!!" << std::endl;
    // Follow Pipelines
    auto hashTable = computeHashTable(
        dataVec, 1<<16, 8, 400, 1<<8
    );

    std::cout << std::vector<double>(hashTable[16389].begin(), hashTable[16389].begin() + 20) << std::endl;

    std::cout << "Constructing Hash Table Done!" << std::endl;
    auto ctxts = encryptTable(
        cc, pk,
        hashTable, 1<<16, 400
    );
    std::cout << "Done!" << std::endl;
}