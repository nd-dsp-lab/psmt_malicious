#include <iostream>
#include <chrono>
#include "openfhe.h"
#include "evenPS.h"
#include "utilsPS.h"
#include "math/chebyshev.h"
#include "chunk_reader.h"
#include <numeric> // For std::accumulate


using namespace lbcrypto;


// Function to compute B(y) = y + (-4/27) * y^3
Ciphertext<DCRTPoly> ComputeB(const Ciphertext<DCRTPoly> &y, 
                              const CryptoContext<DCRTPoly> &cryptoContext) {
    constexpr double coeff = -4.0 / 27.0;
    auto ySquared = cryptoContext->EvalSquare(y);
    auto coeff_y = cryptoContext->EvalMult(y, coeff);
    auto yCubed = cryptoContext->EvalMult(ySquared, coeff_y);
    return cryptoContext->EvalAdd(y, yCubed);
}

// DEP1 function iteratively applies transformation based on L, R, and n
Ciphertext<DCRTPoly> DEP1(double L, double R, int n, 
                          const Ciphertext<DCRTPoly> &x,
                          const CryptoContext<DCRTPoly> &cryptoContext) {
    auto y = x;
    for (int i = n - 1; i >= 0; --i) {
        double L_R_power = pow(L, i) * R;
        double invL_R = 1.0 / L_R_power;
        auto y_scaled = cryptoContext->EvalMult(y, invL_R);
        auto transformed_y = ComputeB(y_scaled, cryptoContext);
        y = cryptoContext->EvalMult(transformed_y, L_R_power);
    }
    return y;
}

Ciphertext<DCRTPoly> signFunc(const Ciphertext<DCRTPoly> &x, const CryptoContext<DCRTPoly> &cc) {

    auto tempMult = cc->EvalMult(1.5, x);
    auto xSquare = cc->EvalSquare(x);
    auto xCube = cc->EvalMult(x, xSquare);
    auto half = cc->EvalMult(0.5, xCube);
    cc->EvalSubInPlace(tempMult, half);
    return tempMult;
}

int main() {
    std::cout << "Initializing program..." << std::endl;

    // Polynomial degree and domain limits
    uint32_t polynomialDegree = 246;
    double lowerBound = -17, upperBound = 17;

    // Define functions for Chebyshev approximation
    auto derivativeHtanFunc = [](double x) -> double {  
        return (1 - tanh(pow(100 * x, 2))); 
    };

    auto inverseFunc = [](double x) -> double {  
        return (pow(x, 2) / (pow(x, 2) + 0.01)); 
    };

    // auto inverseFunc = [](double x) -> double {  
    //     return x / (0.0001 + x); 
    // };

    auto tanh_func = [](double x) -> double {  
        return tanh( 16*x ); 
    };

    // Compute Chebyshev coefficients
    std::vector<double> coeffsHtan = EvalChebyshevCoefficients(
        derivativeHtanFunc, -8.1, 8.1, 58
    );

    std::vector<double> coeffsInverse = EvalChebyshevCoefficients(
        inverseFunc, lowerBound, upperBound, polynomialDegree
    );

    std::vector<double> coeffstanh_func = EvalChebyshevCoefficients(
        tanh_func, lowerBound, upperBound, polynomialDegree
    );

    // CryptoContext parameters
    CCParams<CryptoContextCKKSRNS> cryptoParams;
    cryptoParams.SetScalingTechnique(FLEXIBLEAUTOEXT);
    cryptoParams.SetScalingModSize(59);
    cryptoParams.SetFirstModSize(60);
    cryptoParams.SetMultiplicativeDepth(40);

    cryptoParams.SetRingDim(1 << 17);

    std::cout << "Generating CryptoContext..." << std::endl;
    CryptoContext<DCRTPoly> cryptoContext = GenCryptoContext(cryptoParams);
    cryptoContext->Enable(PKE);
    cryptoContext->Enable(KEYSWITCH);
    cryptoContext->Enable(LEVELEDSHE);
    cryptoContext->Enable(ADVANCEDSHE);

    // Generate key pair
    int32_t n = cryptoContext->GetCryptoParameters()->GetElementParams()->GetCyclotomicOrder() / 2;
    std::vector<int32_t> indexList = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, -n + 2, -n + 3, n - 1, n - 2, -1, -2, -3, -4, -5};
  
    auto keyPair = cryptoContext->KeyGen();
    cryptoContext->EvalMultKeyGen(keyPair.secretKey);
    auto publicKey = keyPair.publicKey;
    cryptoContext->EvalRotateKeyGen(keyPair.secretKey, indexList);

    ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

    std::string filename = "/home/nkoirala/newVAF/data/hashed_chunks.csv";
    std::vector<double> data(65536, 0.0);  // Initialize vector with 65536 elements

    std::vector<double> chunks = ChunkReader::readChunks(filename);
    
    // // Copy first 21 numbers to the beginning of the vector
    // size_t nums_to_copy = std::min(chunks.size(), static_cast<size_t>(21));
    // for (size_t i = 0; i < nums_to_copy; ++i) {
    //     data[i] = chunks[i];
    // }

    // Fill the remaining elements with random double numbers between 1.0 and 2048.0
    // std::random_device rd;
    // std::mt19937 gen(rd());
    // std::uniform_real_distribution<double> dist(1.0, 2048.0);

    // for (size_t i = 21; i < 65536; ++i) {
    //     data[i] = dist(gen);
    // }

    // Print the first few values for verification
    std::cout << "Vector contents (first 30 values):" << std::endl;
    for (size_t i = 0; i < 30; ++i) {
        std::cout << chunks[i] << " ";
    }
    std::cout << std::endl;

    std::string queryFile = "/home/nkoirala/newVAF/data/query.csv";
    std::vector<double> query = ChunkReader::readChunks(queryFile);

    if (query.empty()) {
        std::cerr << "Error: Query file is empty or couldn't be read." << std::endl;
        return 1;
    }

    // Expand query vector to size 65536 by repeating the 7 values sequentially
    std::vector<double> expandedQuery(65536);

    for (size_t i = 0; i < 65536; ++i) {
        expandedQuery[i] = query[i % query.size()];  // Cycle through the 7 values
    }

    // Print first 30 values for verification
    std::cout << "Expanded query vector (first 30 values):" << std::endl;
    for (size_t i = 0; i < 30; ++i) {
        std::cout << expandedQuery[i] << " ";
    }
    std::cout << std::endl;

    Plaintext dbPlain; 
    Ciphertext<DCRTPoly> dbCipher;
    dbPlain = cryptoContext->MakeCKKSPackedPlaintext(chunks);
    dbCipher = cryptoContext->Encrypt(dbPlain, publicKey);

    Plaintext queryPlain; 
    Ciphertext<DCRTPoly> queryCipher;
    queryPlain = cryptoContext->MakeCKKSPackedPlaintext(expandedQuery);
    queryCipher = cryptoContext->Encrypt(queryPlain, publicKey);

    auto res1 = cryptoContext->EvalSub(queryCipher, dbCipher);



    ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
    

// Overall start time
    auto overallStart = std::chrono::high_resolution_clock::now();

    // auto res = signFunc(ciphertext, cryptoContext);
    auto start_dep1 = std::chrono::high_resolution_clock::now();
    auto transformedValue1 = DEP1(2.59, 17, 5, res1, cryptoContext);
    auto end_dep1 = std::chrono::high_resolution_clock::now();
    double time_dep1 = std::chrono::duration<double>(end_dep1 - start_dep1).count();
    std::cout << "Time for first DEP1 transformation: " << time_dep1 << " s" << std::endl;

        // 1. Measure the time for the EvenChebyshevPS inverse operation
    auto start_inv = std::chrono::high_resolution_clock::now();
    auto squareInverse = EvenChebyshevPS(
        cryptoContext,
        transformedValue1,
        coeffsInverse,
        lowerBound,
        upperBound
    );
    auto end_inv = std::chrono::high_resolution_clock::now();
    double time_inv = std::chrono::duration<double>(end_inv - start_inv).count();
    std::cout << "Time for EvenChebyshevPS inverse: " << time_inv << " s" << std::endl;

    //      // 2. Measure the time for the rotation loop (EvalAtIndex and EvalAdd)
    auto start_rot = std::chrono::high_resolution_clock::now();
    size_t block_size = 4;
    for (size_t shift = 1; shift < block_size; ++shift) {
        auto ct_temp = cryptoContext->EvalAtIndex(squareInverse, shift);  
        squareInverse = cryptoContext->EvalAdd(squareInverse, ct_temp);     
    }
    auto end_rot = std::chrono::high_resolution_clock::now();
    double time_rot = std::chrono::duration<double>(end_rot - start_rot).count();
    std::cout << "Time for rotation loop: " << time_rot << " s" << std::endl;

    //     // 6. Measure the time for the final EvenChebyshevPS transformation
    auto start_final = std::chrono::high_resolution_clock::now();
    auto finalResult = EvenChebyshevPS(
        cryptoContext,
        squareInverse,
        coeffsHtan,
        -8.5,
        8.5
    );
    auto end_final = std::chrono::high_resolution_clock::now();
    double time_final = std::chrono::duration<double>(end_final - start_final).count();
    std::cout << "Time for final EvenChebyshevPS: " << time_final << " s" << std::endl;

    auto start_sqr = std::chrono::high_resolution_clock::now();
    cryptoContext->EvalSquareInPlace(finalResult);
    auto end_sqr = std::chrono::high_resolution_clock::now();
    double time_sqr = std::chrono::duration<double>(end_sqr - start_sqr).count();
    std::cout << "Time for squaring: " << time_sqr << " s" << std::endl;

    //     // Overall execution time
    auto overallEnd = std::chrono::high_resolution_clock::now();
    double overallTime = std::chrono::duration<double>(overallEnd - overallStart).count();
    std::cout << "Overall execution time: " << overallTime << " s" << std::endl;

        // Decrypt result
    Plaintext plaintext; 
    cryptoContext->Decrypt(keyPair.secretKey, finalResult, &plaintext);
    std::vector<double> decryptedValues = plaintext->GetRealPackedValue();


    std::cout << "Decrypted Results (first 20): " 
              << std::vector<double>(decryptedValues.begin(), decryptedValues.begin() + 20) 
              << std::endl;

     // Compute the sum of all elements in the vector
    size_t sum = std::accumulate(decryptedValues.begin(), decryptedValues.end(), 0.0);

    std::cout << "Summated value: " << sum << std::endl;

    return 0;
}
