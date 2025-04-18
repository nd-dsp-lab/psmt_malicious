#ifndef LR_UTILS_H
#define LR_UTILS_H

#include <fstream>
#include <sstream>
#include <vector>
#include <string>
#include <iostream>

typedef struct _RawDataBase {
    std::vector<uint64_t> idVec;
    std::vector<uint64_t> answer;
    std::vector<std::vector<double>> payload;
} RawDataBase;

std::vector<double> readParams(
    const std::string& fname
);

RawDataBase readDatabase(
    const std::string& fname,
    const std::string& fnameAns
);

#endif