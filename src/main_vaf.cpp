#include "core.h"
#include "fhe_init.h"
#include "openfhe.h"
#include "tests.h"

int main() {
    testVAFs(
        17,             // k
        4,              // L
        4,              // R
        2,              // n_dep
        3,              // n_vaf
        0,              // n_cleanse
        16              // depth
    );
    return 0;
}