#include "tests.h"

// int main() {
//     // testSingleServer();
//     // testLeaderServer();
//     testFullPipelineRealData();
//     return 0;
// }

void printUsage() {
    std::cerr << "\nUsage: ./main_psmt" << " -DBPath <str>" << " -DBName <str>" << " -isSim <int>" << " -isCompact <int>" << " -numChunks <int>" << " -itemLen <int>\n" ;    
    // std::cerr << "\nUsage: ./main_psmt" << " -DBPath <str>" << " -DBName <str>" << " -isSim <int>" << " -isCompact <int>" << " -numChunks <int>" << " -isHorizontal <int>\n" ;
}


int main(int argc, char* argv[])  {
    const std::string REQUIRED_FLAGS[] = {
        "-DBPath", "-DBName", "-isSim", "-isCompact", "-numChunks", "-itemLen" //, "-isHorizontal"
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
    // std::uint32_t isHorizontal = 0; 
    // isHorizontal = stoi(args["-isHorizontal"]);    

    std::string DBPath = rootDir + DBName + "_prepared.csv";
    std::string ansPath = rootDir + DBName +"_answer.csv";
    std::string paramPath = rootDir + DBName +"_params.bin";


    uint32_t itemLen = stoi(args["-itemLen"]);
    uint32_t actualSize = itemLen * 64;
    
    std::cout << "DB Path: " << DBPath << std::endl;
    std::cout << "Answer Path: " << ansPath << std::endl;
    std::cout << "Parameter Path: " << paramPath << std::endl;
    std::cout << "Item Length (bits): " << actualSize << std::endl;

    // if (isHorizontal) {
    //     if (numChunks == 0) {
    //         throw std::runtime_error("numChunks==0 at Horizontal Segmentation is not supported...");
    //     }
    //     testFullPipelineCompactRealDataHorizontalChunks(DBPath, ansPath, paramPath, isSim, numChunks);        
    //     return 0;
    // }

    if (numChunks == 0) {
        if (isCompact) {
            testFullPipelineCompactRealData(DBPath, ansPath, paramPath, itemLen, isSim);
        } else {
            testFullPipelineRealData(DBPath, ansPath, paramPath, itemLen, isSim);
        }
    } else {
        if (isCompact) {
            testFullPipelineCompactRealDataChunks(DBPath, ansPath, paramPath, itemLen, isSim, numChunks);
        } else {
            testFullPipelineRealDataChunks(DBPath, ansPath, paramPath, itemLen, isSim, numChunks);
        }
    }

    
    return 0;
}