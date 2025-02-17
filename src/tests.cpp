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

int testPoly() {
    std::cout << "Initializing program..." << std::endl;

    // --- FHE Initialization ---
    FHEParams fheParams;
    fheParams.multiplicativeDepth = 40;
    fheParams.scalingModSize = 59;
    fheParams.firstModSize = 60;
    fheParams.ringDim = 1 << 17;
    
    FHEContext fheContext = InitFHE(fheParams);
    auto cryptoContext = fheContext.cryptoContext;
    auto publicKey = fheContext.keyPair.publicKey;

    // --- File Handling ---
    std::string dbFilename = "../data/hashed_chunks.csv";
    std::vector<double> chunks = ChunkReader::readChunks(dbFilename);
    std::cout << "Dataset (first 30 values):" << std::endl;
    for (size_t i = 0; i < 30 && i < chunks.size(); ++i) {
        std::cout << chunks[i] << " ";
    }
    std::cout << std::endl;

    std::string queryFilename = "../data/query.csv";
    std::vector<double> query = ChunkReader::readChunks(queryFilename);
    if (query.empty()) {
        std::cerr << "Error: Query file is empty or couldn't be read." << std::endl;
        return 1;
    }
    std::vector<double> expandedQuery(65536);
    for (size_t i = 0; i < 65536; ++i) {
        expandedQuery[i] = query[i % query.size()];
    }
    std::cout << "Expanded query vector (first 30 values):" << std::endl;
    for (size_t i = 0; i < 30; ++i) {
        std::cout << expandedQuery[i] << " ";
    }
    std::cout << std::endl;

    // --- Encrypt Data ---
    Plaintext dbPlain = cryptoContext->MakeCKKSPackedPlaintext(chunks);
    Ciphertext<DCRTPoly> dbCipher = cryptoContext->Encrypt(dbPlain, publicKey);
    Plaintext queryPlain = cryptoContext->MakeCKKSPackedPlaintext(expandedQuery);
    Ciphertext<DCRTPoly> queryCipher = cryptoContext->Encrypt(queryPlain, publicKey);
    
    // Example operation: compute difference.
    auto ret = cryptoContext->EvalSub(queryCipher, dbCipher);

    // --- Main Cryptographic Computations ---
    auto overallStart = std::chrono::high_resolution_clock::now();

    // Compute VAF 
    cryptoContext->EvalMultInPlace(ret, (double) 0.00048828125);

    // Compute (1 - 3/2 * (1/B)^2 * x^2)^2
    cryptoContext->EvalSquareInPlace(ret);
    cryptoContext->EvalMultInPlace(ret, -1.5);
    cryptoContext->EvalAddInPlace(ret, 1.0);
    cryptoContext->EvalSquareInPlace(ret);

    for (int i = 0; i < 3; i++) {
        ret = compVAFTriple(cryptoContext, ret);
    }

    for (int i = 0; i < 1; i++) {
        ret = compVAFQuad(cryptoContext, ret);
    }    

    for (int i = 0; i < 4; i++) {
        cryptoContext->EvalSquareInPlace(ret);
    }

    for (int i = 0; i < 1; i++) {
        ret = cleanse(cryptoContext, ret);
    }

    Ciphertext<DCRTPoly> _tmp;
    for (int i = 1; i < 4; i++) {
        _tmp = cryptoContext->EvalRotate(ret, i);
        ret = cryptoContext->EvalMult(ret, _tmp);
    }

    for (int i = 0; i < 2; i++) {
        ret = cleanse(cryptoContext, ret);
    }


    auto overallEnd = std::chrono::high_resolution_clock::now();
    double overallTime = std::chrono::duration<double>(overallEnd - overallStart).count();
    std::cout << "Overall execution time: " << overallTime << " s" << std::endl;
    std::cout << "Level: " << ret->GetLevel() << std::endl;

    // --- Decryption and Final Output ---
    Plaintext resultPlain;
    cryptoContext->Decrypt(fheContext.keyPair.secretKey, ret, &resultPlain);
    std::vector<double> decryptedValues = resultPlain->GetRealPackedValue();
    std::cout << "Precision: " << resultPlain->GetLogPrecision() << std::endl;

    std::cout << "Decrypted Results (first 20 values): ";
    for (size_t i = 0; i < 20 && i < decryptedValues.size(); ++i) {
        std::cout << decryptedValues[i] << " ";
    }
    std::cout << std::endl;

    double sum = std::accumulate(decryptedValues.begin(), decryptedValues.end(), 0.0);
    std::cout << "Summated value: " << sum << std::endl;

    return 0;    
}

int testPrev() {
    std::cout << "Initializing program..." << std::endl;

    // --- FHE Initialization ---
    FHEParams fheParams;
    fheParams.multiplicativeDepth = 40;
    fheParams.scalingModSize = 59;
    fheParams.firstModSize = 60;
    fheParams.ringDim = 1 << 17;
    
    FHEContext fheContext = InitFHE(fheParams);
    auto cryptoContext = fheContext.cryptoContext;
    auto publicKey = fheContext.keyPair.publicKey;

    // --- Chebyshev Parameter Setup ---
    ChebyshevConfig htanhConfig {
        [](double x) -> double { return 1 - tanh(pow(100 * x, 2)); },
        -8.5, 8.5, 58
    };

    ChebyshevConfig inverseConfig {
        [](double x) -> double { return (pow(x, 2) / (pow(x, 2) + 0.01)); },
        -17, 17, 246
    };


    std::vector<double> coeffsHtan = ComputeChebyshevCoeffs(htanhConfig);
    std::vector<double> coeffsInverse = ComputeChebyshevCoeffs(inverseConfig);

    // --- File Handling ---
    std::string dbFilename = "../data/hashed_chunks.csv";
    std::vector<double> chunks = ChunkReader::readChunks(dbFilename);
    std::cout << "Dataset (first 30 values):" << std::endl;
    for (size_t i = 0; i < 30 && i < chunks.size(); ++i) {
        std::cout << chunks[i] << " ";
    }
    std::cout << std::endl;

    std::string queryFilename = "../data/query.csv";
    std::vector<double> query = ChunkReader::readChunks(queryFilename);
    if (query.empty()) {
        std::cerr << "Error: Query file is empty or couldn't be read." << std::endl;
        return 1;
    }
    std::vector<double> expandedQuery(65536);
    for (size_t i = 0; i < 65536; ++i) {
        expandedQuery[i] = query[i % query.size()];
    }
    std::cout << "Expanded query vector (first 30 values):" << std::endl;
    for (size_t i = 0; i < 30; ++i) {
        std::cout << expandedQuery[i] << " ";
    }
    std::cout << std::endl;

    // --- Encrypt Data ---
    Plaintext dbPlain = cryptoContext->MakeCKKSPackedPlaintext(chunks);
    Ciphertext<DCRTPoly> dbCipher = cryptoContext->Encrypt(dbPlain, publicKey);
    Plaintext queryPlain = cryptoContext->MakeCKKSPackedPlaintext(expandedQuery);
    Ciphertext<DCRTPoly> queryCipher = cryptoContext->Encrypt(queryPlain, publicKey);
    
    // Example operation: compute difference.
    auto res1 = cryptoContext->EvalSub(queryCipher, dbCipher);

    // --- Main Cryptographic Computations ---
    auto overallStart = std::chrono::high_resolution_clock::now();

    // DEP1 transformation.
    auto start_dep1 = std::chrono::high_resolution_clock::now();
    auto transformedValue1 = DEP1(2.59, 17, 5, res1, cryptoContext);
    auto end_dep1 = std::chrono::high_resolution_clock::now();
    double time_dep1 = std::chrono::duration<double>(end_dep1 - start_dep1).count();
    std::cout << "Time for DEP1 transformation: " << time_dep1 << " s" << std::endl;

    // EvenChebyshevPS inverse operation.
    auto start_inv = std::chrono::high_resolution_clock::now();
    auto squareInverse = EvenChebyshevPS(
        cryptoContext, transformedValue1, coeffsInverse, -17, 17
    );
    auto end_inv = std::chrono::high_resolution_clock::now();
    double time_inv = std::chrono::duration<double>(end_inv - start_inv).count();
    std::cout << "Time for EvenChebyshevPS inverse: " << time_inv << " s" << std::endl;

    // Rotation loop for block summation.
    auto start_rot = std::chrono::high_resolution_clock::now();
    size_t block_size = 4;
    for (size_t shift = 1; shift < block_size; ++shift) {
        auto ct_temp = cryptoContext->EvalAtIndex(squareInverse, shift);
        squareInverse = cryptoContext->EvalAdd(squareInverse, ct_temp);
    }
    auto end_rot = std::chrono::high_resolution_clock::now();
    double time_rot = std::chrono::duration<double>(end_rot - start_rot).count();
    std::cout << "Time for rotation loop: " << time_rot << " s" << std::endl;

    // Final EvenChebyshevPS transformation.
    auto start_final = std::chrono::high_resolution_clock::now();
    auto finalResult = EvenChebyshevPS(cryptoContext, squareInverse, coeffsHtan, -8.5, 8.5);
    auto end_final = std::chrono::high_resolution_clock::now();
    double time_final = std::chrono::duration<double>(end_final - start_final).count();
    std::cout << "Time for final EvenChebyshevPS: " << time_final << " s" << std::endl;

    // Square the final result.
    auto start_sqr = std::chrono::high_resolution_clock::now();
    cryptoContext->EvalSquareInPlace(finalResult);
    auto end_sqr = std::chrono::high_resolution_clock::now();
    double time_sqr = std::chrono::duration<double>(end_sqr - start_sqr).count();
    std::cout << "Time for squaring: " << time_sqr << " s" << std::endl;

    auto overallEnd = std::chrono::high_resolution_clock::now();
    double overallTime = std::chrono::duration<double>(overallEnd - overallStart).count();
    std::cout << "Overall execution time: " << overallTime << " s" << std::endl;

    // --- Decryption and Final Output ---
    Plaintext resultPlain;
    cryptoContext->Decrypt(fheContext.keyPair.secretKey, finalResult, &resultPlain);
    std::vector<double> decryptedValues = resultPlain->GetRealPackedValue();

    std::cout << "Decrypted Results (first 20 values): ";
    for (size_t i = 0; i < 20 && i < decryptedValues.size(); ++i) {
        std::cout << decryptedValues[i] << " ";
    }
    std::cout << std::endl;

    double sum = std::accumulate(decryptedValues.begin(), decryptedValues.end(), 0.0);
    std::cout << "Summated value: " << sum << std::endl;

    return 0;
}
