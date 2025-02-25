#ifndef TEST_H
#define TEST_H

int testPoly();
int testPrev();
int testHb();

int testVAFs(
    // VAF paramaeters
    double k, double L, double R, uint32_t n_dep, uint32_t n_vaf, uint32_t n_cleanse, uint32_t depth
);

#endif