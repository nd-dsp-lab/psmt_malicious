#include "core.h"
#include "fhe_init.h"
#include "openfhe.h"
#include "tests.h"
#include <iostream>
#include <cstdlib>

int main(int argc, char* argv[]) {
     if (argc != 9) {
        std::cerr << "Usage: " << argv[0] << " <k> <L> <R> <n_dep> <n_vaf> <n_cleanse> <depth> <isNewVAF>" << std::endl;
        return 1;
    }

    double k = std::stod(argv[1]);
    double L = std::stod(argv[2]);
    double R = std::stod(argv[3]);
    int n_dep = std::atoi(argv[4]);
    int n_vaf = std::atoi(argv[5]);
    int n_cleanse = std::atoi(argv[6]);
    int depth = std::atoi(argv[7]);
    int isNewVAF = std::atoi(argv[8]);

    testVAFs(k, L, R, n_dep, n_vaf, n_cleanse, depth, isNewVAF);
    return 0;
}
