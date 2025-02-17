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
        derivativeHtanFunc, -8, 8, 58
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
    cryptoParams.SetMultiplicativeDepth(39);

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

    // auto res = signFunc(ciphertext, cryptoContext);
    auto start_dep1 = std::chrono::high_resolution_clock::now();
    auto transformedValue1 = DEP1(2.59, 17, 5, ciphertext, cryptoContext);
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

     // 2. Measure the time for the rotation loop (EvalAtIndex and EvalAdd)
    auto start_rot = std::chrono::high_resolution_clock::now();
    size_t block_size = 4;
    for (size_t shift = 1; shift < block_size; ++shift) {
        auto ct_temp = cryptoContext->EvalAtIndex(squareInverse, shift);  
        squareInverse = cryptoContext->EvalAdd(squareInverse, ct_temp);     
    }
    auto end_rot = std::chrono::high_resolution_clock::now();
    double time_rot = std::chrono::duration<double>(end_rot - start_rot).count();
    std::cout << "Time for rotation loop: " << time_rot << " s" << std::endl;


    // 6. Measure the time for the final EvenChebyshevPS transformation
    auto start_final = std::chrono::high_resolution_clock::now();
    auto finalResult = EvenChebyshevPS(
        cryptoContext,
        squareInverse,
        coeffsHtan,
        -8,
        8
    );
    auto end_final = std::chrono::high_resolution_clock::now();
    double time_final = std::chrono::duration<double>(end_final - start_final).count();
    std::cout << "Time for final EvenChebyshevPS: " << time_final << " s" << std::endl;

    auto start_sqr = std::chrono::high_resolution_clock::now();
    cryptoContext->EvalSquareInPlace(finalResult);
    auto end_sqr = std::chrono::high_resolution_clock::now();
    double time_sqr = std::chrono::duration<double>(end_sqr - start_sqr).count();
    std::cout << "Time for squaring: " << time_sqr << " s" << std::endl;

    // Overall execution time
    auto overallEnd = std::chrono::high_resolution_clock::now();
    double overallTime = std::chrono::duration<double>(overallEnd - overallStart).count();
    std::cout << "Overall execution time: " << overallTime << " s" << std::endl;


    // Decrypt result
    cryptoContext->Decrypt(keyPair.secretKey, finalResult, &plaintext);
    std::vector<double> decryptedValues = plaintext->GetRealPackedValue();

    
    std::cout << "Original Values (first 15): "
              << std::vector<double>(messageVector.begin(), messageVector.begin() + 20) 
              << std::endl;
    std::cout << "Decrypted-transformed Results (first 15): " 
              << std::vector<double>(decryptedValues.begin(), decryptedValues.begin() + 20) 
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
// Time for first DEP1 transformation: 5.83483 s
// Time for EvenChebyshevPS inverse: 7.40954 s
// Time for rotation loop: 0.354894 s
// Time for final EvenChebyshevPS: 1.6798 s
// Overall execution time: 15.2792 s   (total depth required = 39)
// Original Values (first 15): [ 0 0 0 0 0 0 0 1 2 3 500 2048 2048 2048 2048 2048 2048 2048 2048 2048 ]
// Decrypted-transformed Results (first 15): [ 1 0.0925527 0.0618686 -0.0182625 0.0267228 -0.00973723 -0.00838788 
// -0.0132171 -0.177393 0.0130795 0.0152127 0.00739227 0.00739227 0.00739227 0.00739227 0.00739227 0.00739227 
// 0.00739227 0.00739227 0.00739227 ]