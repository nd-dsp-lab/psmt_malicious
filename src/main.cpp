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

int main(int argc, char* argv[]) {
    if (argc != 3) {
        std::cerr << "Usage: " << argv[0] << " <sigma> <kappa>" << std::endl;
        return 1;
    }

    double sigma = std::stod(argv[1]);  
    double kappa = std::stod(argv[2]);  

    testFullPipeline(sigma, kappa);

    return 0;
}
