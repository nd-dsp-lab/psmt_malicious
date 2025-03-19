#ifndef PSMT_TEST_H
#define PSMT_TEST_H

#include "openfhe.h"
#include "server.h"
#include "client.h"
#include "../include/fhe_init.h"
#include "../include/core.h"

using namespace lbcrypto;

void testSingleServer();
void testLeaderServer();

#endif