#include <iostream>
#include <chrono>
#include "openfhe.h"
#include "evenPS.h"
#include "utilsPS.h"
#include "math/chebyshev.h"

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

int main() {
    std::cout << "Initializing program..." << std::endl;

    // Polynomial degree and domain limits
    uint32_t polynomialDegree = 246;
    double lowerBound = -2048, upperBound = 2048;

    // Define functions for Chebyshev approximation
    auto derivativeHtanFunc = [](double x) -> double {  
        return (1 - tanh(pow(100 * x, 2))); 
    };

    auto inverseFunc = [](double x) -> double {  
        return (pow(x, 2) / (pow(x, 2) + 1)); 
    };

    // auto inverseFunc = [](double x) -> double {  
    //     return x / (0.0001 + x); 
    // };

    // Compute Chebyshev coefficients
    std::vector<double> coeffsHtan = EvalChebyshevCoefficients(
        derivativeHtanFunc, -0.16, 0.16, 58
    );

    std::vector<double> coeffsInverse = EvalChebyshevCoefficients(
        inverseFunc, lowerBound, upperBound, polynomialDegree
    );

    // CryptoContext parameters
    CCParams<CryptoContextCKKSRNS> cryptoParams;
    cryptoParams.SetScalingTechnique(FLEXIBLEAUTOEXT);
    cryptoParams.SetScalingModSize(59);
    cryptoParams.SetFirstModSize(60);
    cryptoParams.SetMultiplicativeDepth(47);

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

    // Initialize message vector (plaintext data)
    std::vector<double> messageVector(cryptoContext->GetRingDimension() / 2, 2048);
    messageVector[0] = 0;
    messageVector[1] = 0;
    messageVector[2] = 0;
    messageVector[3] = 0;
    messageVector[4] = 0;
    messageVector[5] = 0;
    messageVector[6] = 0;
    messageVector[7] = 1;
    messageVector[8] = 2;
    messageVector[9] = 3;
    messageVector[10] = 500;

    // Encrypt the plaintext vector
    Plaintext plaintext = cryptoContext->MakeCKKSPackedPlaintext(messageVector);
    Ciphertext<DCRTPoly> ciphertext = cryptoContext->Encrypt(plaintext, publicKey);
// Overall start time
    auto overallStart = std::chrono::high_resolution_clock::now();

    // 1. Measure the time for the EvenChebyshevPS inverse operation
    auto start_inv = std::chrono::high_resolution_clock::now();
    auto squareInverse = EvenChebyshevPS(
        cryptoContext,
        ciphertext,
        coeffsInverse,
        lowerBound,
        upperBound
    );
    auto end_inv = std::chrono::high_resolution_clock::now();
    double time_inv = std::chrono::duration<double>(end_inv - start_inv).count();
    std::cout << "Time for EvenChebyshevPS inverse: " << time_inv << " s" << std::endl;

    // 2. Measure the time for the rotation loop (EvalAtIndex and EvalAdd)
    auto start_rot = std::chrono::high_resolution_clock::now();
    size_t block_size = 4;
    for (size_t shift = 1; shift < block_size; ++shift) {
        auto ct_temp = cryptoContext->EvalAtIndex(squareInverse, shift);  // Rotate within block
        squareInverse = cryptoContext->EvalAdd(squareInverse, ct_temp);     // Sum rotated values
    }
    auto end_rot = std::chrono::high_resolution_clock::now();
    double time_rot = std::chrono::duration<double>(end_rot - start_rot).count();
    std::cout << "Time for rotation loop: " << time_rot << " s" << std::endl;

    // 3. Measure the time for the first DEP1 transformation
    auto start_dep1 = std::chrono::high_resolution_clock::now();
    auto transformedValue1 = DEP1(2.50, 0.19, 4, squareInverse, cryptoContext);
    auto end_dep1 = std::chrono::high_resolution_clock::now();
    double time_dep1 = std::chrono::duration<double>(end_dep1 - start_dep1).count();
    std::cout << "Time for first DEP1 transformation: " << time_dep1 << " s" << std::endl;

    // 4. Measure the time for EvalMult (scaling operation)
    auto start_mult = std::chrono::high_resolution_clock::now();
    auto scaledValue = cryptoContext->EvalMult(transformedValue1, 12);
    auto end_mult = std::chrono::high_resolution_clock::now();
    double time_mult = std::chrono::duration<double>(end_mult - start_mult).count();
    std::cout << "Time for EvalMult (scaling): " << time_mult << " s" << std::endl;

    // 5. Measure the time for the second DEP1 transformation
    auto start_dep2 = std::chrono::high_resolution_clock::now();
    auto transformedValue2 = DEP1(2.50, 0.16, 3, scaledValue, cryptoContext);
    auto end_dep2 = std::chrono::high_resolution_clock::now();
    double time_dep2 = std::chrono::duration<double>(end_dep2 - start_dep2).count();
    std::cout << "Time for second DEP1 transformation: " << time_dep2 << " s" << std::endl;

    // 6. Measure the time for the final EvenChebyshevPS transformation
    auto start_final = std::chrono::high_resolution_clock::now();
    auto finalResult = EvenChebyshevPS(
        cryptoContext,
        transformedValue2,
        coeffsHtan,
        -0.16,
        0.16
    );
    auto end_final = std::chrono::high_resolution_clock::now();
    double time_final = std::chrono::duration<double>(end_final - start_final).count();
    std::cout << "Time for final EvenChebyshevPS: " << time_final << " s" << std::endl;

    // (Optional) If you wish to include the squaring step, you can measure it similarly.
    /*
    auto start_square = std::chrono::high_resolution_clock::now();
    auto squaredFinalResult = cryptoContext->EvalMult(finalResult, 10);
    cryptoContext->EvalSquareInPlace(squaredFinalResult);
    auto end_square = std::chrono::high_resolution_clock::now();
    double time_square = std::chrono::duration<double>(end_square - start_square).count();
    std::cout << "Time for squaring final result: " << time_square << " s" << std::endl;
    */

    // Overall execution time
    auto overallEnd = std::chrono::high_resolution_clock::now();
    double overallTime = std::chrono::duration<double>(overallEnd - overallStart).count();
    std::cout << "Overall execution time: " << overallTime << " s" << std::endl;


    // Decrypt result
    cryptoContext->Decrypt(keyPair.secretKey, finalResult, &plaintext);
    std::vector<double> decryptedValues = plaintext->GetRealPackedValue();

    
    std::cout << "Original Values (first 15): "
              << std::vector<double>(messageVector.begin(), messageVector.begin() + 15) 
              << std::endl;
    std::cout << "Decrypted-transformed Results (first 15): " 
              << std::vector<double>(decryptedValues.begin(), decryptedValues.begin() + 15) 
              << std::endl;

    return 0;
}


// nkoirala@tjws-05:~/newVAF/build$ ./run.sh 
// [ 60%] Built target newVAF
// Scanning dependencies of target main
// [ 80%] Building CXX object CMakeFiles/main.dir/src/main.cpp.o
// [100%] Linking CXX executable main
// [100%] Built target main
// Initializing program...
// Generating CryptoContext...
// Time for EvenChebyshevPS inverse: 41.0982 s
// Time for rotation loop: 3.26445 s
// Time for first DEP1 transformation: 9.03085 s
// Time for EvalMult (scaling): 0.0569334 s
// Time for second DEP1 transformation: 3.40097 s
// Time for final EvenChebyshevPS: 3.66925 s
// Overall execution time: 60.5209 s  (total depth required = 47)
// Original Values (first 15): [ 0 0 0 0 0 0 0 1 2 3 500 2048 2048 2048 2048 ]
// Decrypted-transformed Results (first 15): [ 1 -0.0168468 0.00229025 -0.00367201 0.00634756
//  0.0026371 -0.00788329 0.00256785 -0.00140552 0.00424272 -0.00473382 -0.0130385 -0.0130385
//   -0.0130385 -0.0130385 ]