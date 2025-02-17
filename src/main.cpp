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

int main() {
    testPoly();
    // testPrev();
}

// int main() {
//     std::cout << "Initializing program..." << std::endl;

//     // --- FHE Initialization ---
//     FHEParams fheParams;
//     fheParams.multiplicativeDepth = 40;
//     fheParams.scalingModSize = 59;
//     fheParams.firstModSize = 60;
//     fheParams.ringDim = 1 << 17;
    
//     FHEContext fheContext = InitFHE(fheParams);
//     auto cryptoContext = fheContext.cryptoContext;
//     auto publicKey = fheContext.keyPair.publicKey;

//     // ----- DEP constants -----------
//     // double L = DEPConstants::DEFAULT_L;
//     // double R = DEPConstants::DEFAULT_R;
//     // int dep_n = DEPConstants::DEFAULT_N;

//     // --- Chebyshev Parameter Setup ---

//     // ChebyshevConfig htanhConfig {
//     //     [](double x) -> double { return 1 - tanh(pow(100 * x, 2)); },
//     //     ChebyshevConstants::HTAN_LOWER_BOUND,
//     //     ChebyshevConstants::HTAN_UPPER_BOUND,
//     //     ChebyshevConstants::DEFAULT_DEGREE_HTAN
//     // };

//     // ChebyshevConfig inverseConfig {
//         // [](double x) -> double { return (pow(x, 2) / (pow(x, 2) + 0.01)); },
//         // ChebyshevConstants::INVERSE_LOWER_BOUND,
//         // ChebyshevConstants::INVERSE_UPPER_BOUND,
//         // ChebyshevConstants::DEFAULT_DEGREE_INVERSE
//         // -2048, 2048, 16
//     // };


//     // std::vector<double> coeffsHtan = ComputeChebyshevCoeffs(htanhConfig);
//     // std::vector<double> coeffsInverse = ComputeChebyshevCoeffs(inverseConfig);

//     // --- File Handling ---
//     std::string dbFilename = "../data/hashed_chunks.csv";
//     std::vector<double> chunks = ChunkReader::readChunks(dbFilename);
//     std::cout << "Dataset (first 30 values):" << std::endl;
//     for (size_t i = 0; i < 30 && i < chunks.size(); ++i) {
//         std::cout << chunks[i] << " ";
//     }
//     std::cout << std::endl;

//     std::string queryFilename = "../data/query.csv";
//     std::vector<double> query = ChunkReader::readChunks(queryFilename);
//     if (query.empty()) {
//         std::cerr << "Error: Query file is empty or couldn't be read." << std::endl;
//         return 1;
//     }
//     std::vector<double> expandedQuery(65536);
//     for (size_t i = 0; i < 65536; ++i) {
//         expandedQuery[i] = query[i % query.size()];
//     }
//     std::cout << "Expanded query vector (first 30 values):" << std::endl;
//     for (size_t i = 0; i < 30; ++i) {
//         std::cout << expandedQuery[i] << " ";
//     }
//     std::cout << std::endl;

//     // --- Encrypt Data ---
//     Plaintext dbPlain = cryptoContext->MakeCKKSPackedPlaintext(chunks);
//     Ciphertext<DCRTPoly> dbCipher = cryptoContext->Encrypt(dbPlain, publicKey);
//     Plaintext queryPlain = cryptoContext->MakeCKKSPackedPlaintext(expandedQuery);
//     Ciphertext<DCRTPoly> queryCipher = cryptoContext->Encrypt(queryPlain, publicKey);
    
//     // Example operation: compute difference.
//     auto ret = cryptoContext->EvalSub(queryCipher, dbCipher);

//     // --- Main Cryptographic Computations ---
//     auto overallStart = std::chrono::high_resolution_clock::now();

//     // Compute VAF 
//     cryptoContext->EvalMultInPlace(ret, (double) 0.00048828125);

//     // Compute (1 - 3/2 * (1/B)^2 * x^2)^2
//     cryptoContext->EvalSquareInPlace(ret);
//     cryptoContext->EvalMultInPlace(ret, -1.5);
//     cryptoContext->EvalAddInPlace(ret, 1.0);
//     cryptoContext->EvalSquareInPlace(ret);

//     // ret = EvenChebyshevPS(cryptoContext, ret, coeffsInverse, -2048, 2048);
//     // cryptoContext->EvalSquareInPlace(ret);

//     for (int i = 0; i < 3; i++) {
//         ret = compVAFQuad(cryptoContext, ret);
//     }

//     for (int i = 0; i < 4; i++) {
//         cryptoContext->EvalSquareInPlace(ret);
//     }

//     for (int i = 0; i < 1; i++) {
//         ret = cleanse(cryptoContext, ret);
//     }

//     Ciphertext<DCRTPoly> _tmp;
//     for (int i = 1; i < 4; i++) {
//         _tmp = cryptoContext->EvalRotate(ret, i);
//         cryptoContext->EvalAddInPlace(ret, _tmp);
//     }
//     cryptoContext->EvalMultInPlace(ret, 0.125);

//     for (int i = 0; i < 6; i++) {
//         cryptoContext->EvalSquareInPlace(ret);
//     }

//     for (int i = 0; i < 2; i++) {
//         ret = cleanse(cryptoContext, ret);
//     }    

//     auto overallEnd = std::chrono::high_resolution_clock::now();
//     double overallTime = std::chrono::duration<double>(overallEnd - overallStart).count();
//     std::cout << "Overall execution time: " << overallTime << " s" << std::endl;
//     std::cout << "Level: " << ret->GetLevel() << std::endl;

//     // --- Decryption and Final Output ---
//     Plaintext resultPlain;
//     cryptoContext->Decrypt(fheContext.keyPair.secretKey, ret, &resultPlain);
//     std::vector<double> decryptedValues = resultPlain->GetRealPackedValue();
//     std::cout << "Precision: " << resultPlain->GetLogPrecision() << std::endl;

//     std::cout << "Decrypted Results (first 20 values): ";
//     for (size_t i = 0; i < 20 && i < decryptedValues.size(); ++i) {
//         std::cout << decryptedValues[i] << " ";
//     }
//     std::cout << std::endl;

//     double sum = std::accumulate(decryptedValues.begin(), decryptedValues.end(), 0.0);
//     std::cout << "Summated value: " << sum << std::endl;

//     return 0;
// }
