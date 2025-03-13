#include <iostream>
#include <chrono>
#include <numeric>
#include "openfhe.h"
#include "fhe_init.h"
#include "dep.h"
#include "evenPS.h"
#include "chebyshev_config.h"
#include "chunk_reader.h"  // Assumed to provide ChunkReader::readChunks
#include "vaf.h"
#include "tests.h"

using namespace lbcrypto;

int main() {
    testFullNewVAF();
}