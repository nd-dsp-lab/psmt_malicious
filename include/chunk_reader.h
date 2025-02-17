#ifndef CHUNK_READER_H
#define CHUNK_READER_H

#include <iostream>
#include <fstream>
#include <vector>
#include <sstream>
#include <string>

class ChunkReader {
public:
    static std::vector<double> readChunks(const std::string& filename) {
        std::ifstream inputFile(filename);
        std::vector<double> chunks;

        if (!inputFile.is_open()) {
            std::cerr << "Error opening file: " << filename << std::endl;
            return chunks;
        }

        std::string line;
        bool firstLine = true;  // Skip header

        while (std::getline(inputFile, line)) {
            if (firstLine) {
                firstLine = false;  // Skip the first row (header)
                continue;
            }

            std::istringstream ss(line);
            double chunk;
            ss >> chunk;  // Convert string to double

            if (ss.fail()) continue;  // Handle any parsing errors

            chunks.push_back(chunk);
        }

        inputFile.close();
        return chunks;
    }
};

#endif // CHUNK_READER_H
