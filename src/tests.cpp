#include <iostream>
#include <chrono>
#include <numeric>
#include <cmath>     // for std::ceil, std::log2
#include <vector>
#include "openfhe.h"
#include "fhe_init.h"
#include "dep.h"
#include "evenPS.h"
#include "chebyshev_config.h"
#include "chunk_reader.h"  // Assumed to provide ChunkReader::readChunks
#include "vaf.h"
#include "core.h"



int32_t NextPowerOfTwo(int32_t n) {
    if (n < 1) return 1;
    // ceil(log2(n)) gives the exponent of the smallest power-of-two >= n
    int32_t exp = static_cast<int32_t>(std::ceil(std::log2(n)));
    return (1 << exp); // 2^exp
}

void GenerateRotationKeys(CryptoContext<DCRTPoly> cryptoContext,
                                       PrivateKey<DCRTPoly> secretKey,
                                       int32_t N) {
    // 1) Compute the next power of 2 (P) >= N
    int32_t P = NextPowerOfTwo(N);

    // 2) Generate rotation indices: P/2, P/4, ..., 1
    std::vector<int32_t> indexList;
    int32_t step = P / 2;
    while (step > 0) {
        indexList.push_back(step);
        step /= 2;
    }

    // 3) Generate rotation keys for just these indices
    cryptoContext->EvalRotateKeyGen(secretKey, indexList);

    // For debugging
    std::cout << "Rotation indices needed to preserve slots for kappa=" << N << ": ";
    for (auto idx : indexList) {
        std::cout << idx << " ";
    }
    std::cout << std::endl;
}


Ciphertext<DCRTPoly> preserveSlotZero(
    Ciphertext<DCRTPoly> ct,              // ciphertext with kappa number of chunks -> kappa must be a power of two
    CryptoContext<DCRTPoly> cryptoContext,
    size_t kappa                            
) {
    size_t step = kappa >> 1; // half of kappa

    while (step > 0) {
        // 1) Rotate by step
        auto rotated = cryptoContext->EvalRotate(ct, step);

        // 2) Multiply => forces the side that lines up with zero to remain zero
        //    and keeps slot 0 if it's not aligned to zero
        ct = cryptoContext->EvalMult(ct, rotated);

        step >>= 1; // step = step / 2
    }

    return ct;
}

Ciphertext<DCRTPoly> sumAllSlots(Ciphertext<DCRTPoly> ct,
                                 CryptoContext<DCRTPoly> cryptoContext,
                                 size_t originalSize) {
    // 1) Find next power of 2
    size_t P = NextPowerOfTwo(originalSize);

    // 2) If the ciphertext is already padded to P slots, skip. Otherwise pad it.

    // 3) Start the half-interval and do repeated rotate+add
    size_t offset = P / 2;
    while (offset >= 1) {
        auto rotatedCT = cryptoContext->EvalRotate(ct, offset);
        ct = cryptoContext->EvalAdd(ct, rotatedCT);
        offset /= 2; // go to the next half
    }

    return ct; // slot i, i+originalSize, i+ 2*originalSize, .. now contains the sum
}



int testFullPipeline(double sigma, double kappa) {

    std::cout << "Initializing program..." << std::endl;

    // setting VAF params based on kappa and sigma
    int exponent = sigma / kappa; // integer division
    int domain   = 1 << exponent; // 2^exponent

    double k      = 0.0;
    int    L      = 0;
    double R      = 0.0;
    int    n_dep  = 0;
    int    n_vaf  = 0;
    int    depth  = 0;
    bool   isNewVAF = false;

    // setting up the VAF parameters
    setupVAFParams(sigma, kappa, k, L, R, n_dep, n_vaf, depth, isNewVAF);

    std::cout << "Running the protocol for domain size = " << domain << ", and kappa = "
              << kappa << std::endl;
    std::cout << "VAF and weakDEP params: k=" << k 
              << ", L=" << L << ", R=" << R
              << ", n_dep=" << n_dep << ", n_vaf=" << n_vaf 
              << ", depth=" << depth << std::endl << std::endl;


    // --- FHE Initialization ---
    FHEParams fheParams;
    fheParams.multiplicativeDepth = depth;
    fheParams.scalingModSize = 59;
    fheParams.firstModSize = 60;
    fheParams.ringDim = 1 << 17;
    
    FHEContext fheContext = InitFHE(fheParams);
    auto cryptoContext = fheContext.cryptoContext;
    auto publicKey = fheContext.keyPair.publicKey;
    auto secretKey = fheContext.keyPair.secretKey;

    GenerateRotationKeys(cryptoContext, secretKey, kappa);
    size_t slots = fheParams.ringDim/2; // Maximum size per ciphertext in CKKS


    // --- File Handling ---
    std::string dbFilename = "../data/" + std::to_string((int)sigma) + "_bits/hashed_chunks_"
                             + std::to_string((int)sigma) + "_" + std::to_string((int)kappa) + ".csv";

    std::vector<double> chunks = ChunkReader::readChunks(dbFilename);
    std::cout << "Dataset (first 30 values):" << std::endl;
    for (size_t i = 0; i < 30 && i < chunks.size(); ++i) {
        std::cout << chunks[i] << " ";
    }
    std::cout << std::endl;
    std::cout << "\nSize of chunks vector: " << chunks.size() << std::endl;
    std::cout << std::endl;

    // Query file
    std::string queryFilename = "../data/" + std::to_string((int)sigma)
                                + "_bits/query/hashed_chunks_"
                                + std::to_string((int)sigma) + "_" 
                                + std::to_string((int)kappa) + "_query.csv";

    std::vector<double> query = ChunkReader::readChunks(queryFilename);
    if (query.empty()) {
        std::cerr << "Error: Query file is empty or couldn't be read." << std::endl;
        return 1;
    }
    query.resize(kappa);
    std::vector<double> expandedQuery(slots);
    for (size_t i = 0; i < slots; ++i) {
        expandedQuery[i] = query[i % query.size()];
    }
    std::cout << "Expanded query vector (first 30 values):" << std::endl;
    for (size_t i = 0; i < 30; ++i) {
        std::cout << expandedQuery[i] << " ";
    }
    std::cout << std::endl;

    
    // --- Encrypt Data -------------------------------------------

    size_t numCiphertexts = (chunks.size() + slots - 1) / slots; // Calculate required ciphertexts
    std::vector<Ciphertext<DCRTPoly>> encryptedChunks;

    // Define a fallback value to pad out vectors
    double dummyValue = (double)domain - 1;

    #pragma omp parallel for num_threads(MAX_NUM_CORES)
    for (size_t i = 0; i < numCiphertexts; ++i) {
        size_t startIdx = i * slots;
        size_t endIdx = std::min(startIdx + slots, chunks.size());
        std::vector<double> chunkSegment(chunks.begin() + startIdx, chunks.begin() + endIdx);
        
        // Pad with 255 if this is the last chunk and not fully filled
        if (chunkSegment.size() < slots) {
            chunkSegment.resize(slots, dummyValue);
        }
        
        Plaintext dbPlain = cryptoContext->MakeCKKSPackedPlaintext(chunkSegment);
        Ciphertext<DCRTPoly> dbCipher = cryptoContext->Encrypt(dbPlain, publicKey);
        encryptedChunks.push_back(dbCipher);
    }

    Plaintext queryPlain = cryptoContext->MakeCKKSPackedPlaintext(expandedQuery);
    Ciphertext<DCRTPoly> queryCipher = cryptoContext->Encrypt(queryPlain, publicKey);

    std::cout << "Successfully encrypted " << encryptedChunks.size() << " ciphertexts." << std::endl;

    // ------------------------------------------------------------


    // --- Main Cryptographic Computations ---
    auto overallStart = std::chrono::high_resolution_clock::now();

    #pragma omp parallel for num_threads(MAX_NUM_CORES)
    for (size_t i = 0; i < encryptedChunks.size(); ++i) {
        encryptedChunks[i] = cryptoContext->EvalSub(queryCipher, encryptedChunks[i]);
    }
    
    // Compute VAF for all ciphertexts in parallel
    #pragma omp parallel for num_threads(MAX_NUM_CORES)
    for (size_t i = 0; i < encryptedChunks.size(); ++i) {
        encryptedChunks[i] = fusedVAF(
            cryptoContext, encryptedChunks[i], 
            k, L, R, n_dep, n_vaf, 0, isNewVAF
        );
        encryptedChunks[i] = preserveSlotZero(encryptedChunks[i], cryptoContext, kappa);
    }
    
    auto res = cryptoContext->EvalAddMany(encryptedChunks);

    // Multiplying the masking Vector
    std::vector<double> maskVec(slots, 0);
    for (uint32_t i = 0; i < slots; i = i + kappa) {
        maskVec[i] = 1.0;
    }
    auto maskPtxt = cryptoContext->MakeCKKSPackedPlaintext(maskVec);
    res = cryptoContext->EvalMult(res, maskPtxt);

    auto overallEnd = std::chrono::high_resolution_clock::now();
    double overallTime = std::chrono::duration<double>(overallEnd - overallStart).count();
    std::cout << "Overall execution time: " << overallTime << " s" << std::endl;
    std::cout << "Level: " << res->GetLevel() << std::endl;

    // --- Decryption and Final Output ---
    Plaintext resultPlain;
    cryptoContext->Decrypt(fheContext.keyPair.secretKey, res, &resultPlain);
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


// Full Pipeline using New VAF
int testFullNewVAF() {
    std::cout << "Initializing program..." << std::endl;

    // --- FHE Initialization ---
    FHEParams fheParams;
    fheParams.multiplicativeDepth = 30;
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
    // Assume that each slot contains 11-bit elements
    // VAF for 2^12
    // It takes 25 depths
    ret = fusedVAF(
        cryptoContext, ret, 
        6.75, 2.59, 91.09, 4, 7, 0, true
    );

    // Rotate & Multiply
    Ciphertext<DCRTPoly> _tmp;
    for (int i = 1; i < 4; i++) {
        _tmp = cryptoContext->EvalRotate(ret, i);
        ret = cryptoContext->EvalMult(ret, _tmp);
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

// Full Pipeline using Chebyshev Approximation
int testFullPrev() {
    std::cout << "Initializing program..." << std::endl;

    // --- FHE Initialization ---
    FHEParams fheParams;
    fheParams.multiplicativeDepth = 30;
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

    // DEP2 transformation.
    auto start_dep1 = std::chrono::high_resolution_clock::now();
    auto transformedValue1 = DEP2(2.58, 17, 5, 27/4, res1, cryptoContext);
    auto end_dep1 = std::chrono::high_resolution_clock::now();
    double time_dep1 = std::chrono::duration<double>(end_dep1 - start_dep1).count();
    std::cout << "Time for DEP2 transformation: " << time_dep1 << " s" << std::endl;

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
    // for (int i = 0; i < 2; i++) {
    //     finalResult = cleanse(cryptoContext, finalResult);
    // }
    auto end_sqr = std::chrono::high_resolution_clock::now();
    double time_sqr = std::chrono::duration<double>(end_sqr - start_sqr).count();
    std::cout << "Time for squaring: " << time_sqr << " s" << std::endl;

    auto overallEnd = std::chrono::high_resolution_clock::now();
    double overallTime = std::chrono::duration<double>(overallEnd - overallStart).count();
    std::cout << "Overall execution time: " << overallTime << " s" << std::endl;
    std::cout << "Level: " << finalResult->GetLevel() << std::endl;

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


// Test code for VAFs Only
int testVAFs(
    // VAF paramaeters
    double k, double L, double R, uint32_t n_dep, uint32_t n_vaf, uint32_t n_cleanse, uint32_t depth, bool isNewVAF
) {
    std::cout << "Initializing program..." << std::endl;
    // --- FHE Initialization ---
    FHEParams fheParams;
    fheParams.multiplicativeDepth = depth;
    fheParams.scalingModSize = 50;
    fheParams.firstModSize = 60;
    fheParams.ringDim = 1 << 17;

    FHEContext fheContext = InitFHE(fheParams);
    auto cc = fheContext.cryptoContext;
    auto publicKey = fheContext.keyPair.publicKey;

    // Setup the dummy values
    std::vector<double> msgVec(1 << 16, 0.0);
    double logRange = n_dep * std::log2(L) + std::log2(R);
    int intRange = 1 << (int)std::floor(logRange);

    for (double i = 0; i < 65535; i++) {
        msgVec[i] = intRange - 1;
    }   
    msgVec[0] = 0;
    msgVec[1] = 1;
    msgVec[2] = -1;

    auto ptxt = cc->MakeCKKSPackedPlaintext(msgVec);
    auto ctxt = cc->Encrypt(ptxt, publicKey);

    // Start the test 
    std::cout << "<-------- VAF TEST START ---------->" << std::endl;
    std::cout << "k: \t\t" << k << std::endl;
    std::cout << "L: \t\t" << L << std::endl;
    std::cout << "R: \t\t" << R << std::endl;
    std::cout << "n_dep: \t\t" << n_dep << std::endl;
    std::cout << "n_vaf: \t\t" << n_vaf << std::endl;
    std::cout << "Range (log2): \t" << logRange << std::endl;

    auto start = std::chrono::high_resolution_clock::now();
    auto ret = fusedVAF(cc, ctxt, k, L, R, n_dep, n_vaf, n_cleanse, isNewVAF);
    auto end = std::chrono::high_resolution_clock::now();
    auto timeRet = std::chrono::duration<double>(end - start).count();
    std::cout << "Overall execution time: " << timeRet << " s" << std::endl;
    std::cout << "Level: " << ret->GetLevel() << std::endl;
    // Decrypt
    Plaintext retPtxt;
    cc->Decrypt(fheContext.keyPair.secretKey, ret, &retPtxt);
    std::cout << "Precision: " << retPtxt->GetLogPrecision() << std::endl;

    // Get Values and Print Values
    std::vector<double> retVec = retPtxt->GetRealPackedValue();
    std::cout << "Print First 20 Values:"  << std::endl;
    std::cout << std::vector<double>(retVec.begin(), retVec.begin() + 20) << std::endl;

    // Done!
    return 0;
}