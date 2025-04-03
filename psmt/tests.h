#ifndef PSMT_TEST_H
#define PSMT_TEST_H

#include "openfhe.h"
#include "server.h"
#include "client.h"
#include "../include/fhe_init.h"
#include "../include/core.h"
#include "../logreg/utils.h"

#include <string>

#define MAX_NUM_CORES 48

using namespace lbcrypto;

void testSingleServer();
void testLeaderServer();

void testFullPipelineRealData(
    std::string DBPath, 
    std::string ansPath, 
    std::string paramPath, 
    uint32_t itemLen,
    bool isSim,
    int scalingMod
);

void testFullPipelineCompactRealData(
    std::string DBPath, 
    std::string ansPath, 
    std::string paramPath, 
    uint32_t itemLen,
    bool isSim,
    int scalingMod
);


void testFullPipelineRealDataChunks(
    std::string DBPath, 
    std::string ansPath, 
    std::string paramPath, 
    uint32_t itemLen,
    bool isSim,
    int scalingMod,
    uint32_t numChunks
);

void testFullPipelineCompactRealDataChunks(
    std::string DBPath, 
    std::string ansPath, 
    std::string paramPath, 
    uint32_t itemLen,
    bool isSim,
    int scalingMod,
    uint32_t numChunks
);

// void testFullPipelineCompactRealDataHorizontalChunks(
//     std::string DBPath, 
//     std::string ansPath, 
//     std::string paramPath, 
//     bool isSim,
//     uint32_t numChunks
// );

#endif

