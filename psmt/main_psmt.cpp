#include "tests.h"

// int main() {
//     // testSingleServer();
//     // testLeaderServer();
//     testFullPipelineRealData();
//     return 0;
// }

void printUsage() {
    std::cerr << "\nUsage: ./main_psmt" << " -DBPath <str>" << " -DBName <str>" << " -isSim <int>" << " -isCompact <int>" << " -numChunks <int>\n" ;
}


int main(int argc, char* argv[])  {
    const std::string REQUIRED_FLAGS[] = {
        "-DBPath", "-DBName", "-isSim", "-isCompact", "-numChunks"
    };

    std::map<std::string, std::string> args;
    for (int i = 1; i < argc - 1; i+= 2) {
        std::string key = argv[i];
        std::string value = argv[i+1];

        if (key.size() > 1 && key[0] == '-') {
            args[key] = value;
        } else {
            std::cerr << "Error: Invalid Flag '" << key << "'.\n";
            printUsage();
            return 1;
        }
    }

    for (const auto& flag: REQUIRED_FLAGS) {
        if (args.find(flag) == args.end()) {
            std::cerr << "Error: Missing Required flag '" << flag << "'\n";
            printUsage();
            return 1;
        }
    }

    std::string rootDir = args["-DBPath"];
    std::string DBName = args["-DBName"];
    bool isSim = true;
    if (args["-isSim"] == "1") {
        isSim = true;
    } else {
        isSim = false;
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
    std::string ansPath = rootDir + DBName +"_answer.csv";
    std::string paramPath = rootDir + DBName +"_params.bin";

    std::cout << "DB Path: " << DBPath << std::endl;
    std::cout << "Answer Path: " << ansPath << std::endl;
    std::cout << "Parameter Path: " << paramPath << std::endl;

    if (numChunks == 0) {
        if (isCompact) {
            testFullPipelineCompactRealData(DBPath, ansPath, paramPath, isSim);
        } else {
            testFullPipelineRealData(DBPath, ansPath, paramPath, isSim);
        }
    } else {
        if (isCompact) {
            testFullPipelineCompactRealDataChunks(DBPath, ansPath, paramPath, isSim, numChunks);
        } else {
            testFullPipelineRealDataChunks(DBPath, ansPath, paramPath, isSim, numChunks);
        }
    }

    
    return 0;
}