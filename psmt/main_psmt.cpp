#include "tests.h"

// int main() {
//     // testSingleServer();
//     // testLeaderServer();
//     testFullPipelineRealData();
//     return 0;
// }


void printUsage() {

    std::cerr << "\nUsage: ./main_psmt"
              << " -DBPath <str>"
              << " -DBName <str>"
              << " -isSim <int>"
              << " -isCompact <int>"
              << " -scalingModSize <int> (optional, max 59)\n"
              << " -isCompact <int>";
}

int main(int argc, char* argv[]) {
    const std::string REQUIRED_FLAGS[] = {

        "-DBPath", "-DBName", "-isSim", "-isCompact", "-scalingModSize", "-numChunks"

    };

    std::map<std::string, std::string> args;
    for (int i = 1; i < argc - 1; i += 2) {
        std::string key = argv[i];
        std::string value = argv[i + 1];

        if (key.size() > 1 && key[0] == '-') {
            args[key] = value;
        } else {
            std::cerr << "Error: Invalid Flag '" << key << "'.\n";
            printUsage();
            return 1;
        }
    }

    for (const auto& flag : REQUIRED_FLAGS) {
        if (args.find(flag) == args.end()) {
            std::cerr << "Error: Missing Required flag '" << flag << "'\n";
            printUsage();
            return 1;
        }
    }

    // Parse required args
    std::string rootDir = args["-DBPath"];
    std::string DBName = args["-DBName"];
    bool isSim = (args["-isSim"] == "1");
    bool isCompact = (args["-isCompact"] == "1");

    // Parse optional scalingModSize
    uint32_t scalingModSize = 59; // Default value
    if (args.find("-scalingModSize") != args.end()) {
        scalingModSize = std::stoi(args["-scalingModSize"]);
        if (scalingModSize > 59) {
            std::cerr << "Error: -scalingModSize cannot be greater than 59.\n";
            return 1;
        }
    }

    bool isCompact = true;
    if (args["-isCompact"] == "1") {
        isCompact = true;
    } else {
        isCompact = false;
    }    
    std::uint32_t numChunks = 0; 
    numChunks = stoi(args["-numChunks"]);



    std::string DBPath = rootDir + DBName + "_prepared.csv";
    std::string ansPath = rootDir + DBName + "_answer.csv";
    std::string paramPath = rootDir + DBName + "_params.bin";

    std::cout << "DB Path: " << DBPath << std::endl;
    std::cout << "Answer Path: " << ansPath << std::endl;
    std::cout << "Parameter Path: " << paramPath << std::endl;
    std::cout << "Scaling Mod Size: " << scalingModSize << std::endl;


    if (numChunks == 0) {
        if (isCompact) {
            testFullPipelineCompactRealData(DBPath, ansPath, paramPath, isSim, scalingModSize);
        } else {
            testFullPipelineRealData(DBPath, ansPath, paramPath, isSim, scalingModSize);
        }
    } else {
        if (isCompact) {
            testFullPipelineCompactRealDataChunks(DBPath, ansPath, paramPath, isSim, scalingModSize, numChunks);
        } else {
            testFullPipelineRealDataChunks(DBPath, ansPath, paramPath, isSim, scalingModSize, numChunks);
        }
    }

    
    return 0;
}
