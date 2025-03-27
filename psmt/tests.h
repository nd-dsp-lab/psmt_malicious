#ifndef PSMT_TEST_H
#define PSMT_TEST_H

#include "openfhe.h"
#include "server.h"
#include "client.h"
#include "../include/fhe_init.h"
#include "../include/core.h"
#include "../logreg/utils.h"

#include <string>

using namespace lbcrypto;

void testSingleServer();
void testLeaderServer();
void testFullPipelineRealData(
    std::string DBPath, 
    std::string ansPath, 
    std::string paramPath,
    bool isSim
);

void testFullPipelineCompactRealData(
    std::string DBPath, 
    std::string ansPath, 
    std::string paramPath, 
    bool isSim
);

#endif