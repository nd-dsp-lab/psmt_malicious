#include "utils.h"

// Code for reading parameters
std::vector<double> readParams(const std::string& fname) {
    std::ifstream file(fname, std::ios::binary);

    // Read Parameters
    std::vector<double> params;
    double _tmp;
    while (file.read(reinterpret_cast<char*>(&_tmp), sizeof(double))) {
        params.push_back(_tmp);
    }
    file.close();
    return params;
}


// Code for reading the database 
CancerDB readDatabase(const std::string& fname) {
    std::ifstream file(fname);
    std::vector<uint64_t> idVec;
    std::vector<uint64_t> answer;
    std::vector<std::vector<double>> payload;
    std::vector<double> meanVal;


    // Read Data
    std::string line;
    std::getline(file, line);

    std::cout << "HEADER OF THE DATABASE: " << std::endl;
    std::cout << line << std::endl;

    while (std::getline(file, line)) {
        std::vector<std::string> row;
        std::stringstream ss(line);
        std::string cell;
        
        // Interpret the data
        while (std::getline(ss, cell, ',')) {
            row.push_back(cell);
        }
        
        // for (uint32_t i = 0; i < row.size(); i++) {
        //     std::cout << row[i] << " ";
        // }
        // std::cout << std::endl;

        idVec.push_back(stoi(row[0]));

        std::vector<double> buf;

        if (row[1] == "M") {
            answer.push_back(1);
        } else {
            answer.push_back(0);
        }

        for (uint32_t i = 2; i < row.size(); i++) {
            buf.push_back(stod(row[i]));
        }
        payload.push_back(buf);        
    }
 
    return CancerDB {
        idVec, answer, payload
    };
}