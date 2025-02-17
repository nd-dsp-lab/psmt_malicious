#include <iostream>
#include "openfhe.h"
#include "evenPS.h"
#include "utilsPS.h"
#include "math/chebyshev.h"
#include "chunk_reader.h"

#include <chrono>

using namespace lbcrypto;

// DEP functions
Ciphertext<DCRTPoly> B(const Ciphertext<DCRTPoly> &y,
                       const CryptoContext<DCRTPoly> &cryptoContext) {
  constexpr double coeff = -4.0 / 27.0;
  auto y2 = cryptoContext->EvalSquare(y);
  auto coeff_y = cryptoContext->EvalMult(y, coeff);
  auto final_y = cryptoContext->EvalMult(y2, coeff_y);
  auto tempC = cryptoContext->EvalAdd(y, final_y);
  return tempC;
}

Ciphertext<DCRTPoly> DEP1(const double L, const double R, const int n,
                          const Ciphertext<DCRTPoly> &x,
                          const CryptoContext<DCRTPoly> &cryptoContext) {

  auto y = x;
  Ciphertext<DCRTPoly> temp_y;
  for (int i = n - 1; i >= 0; --i) {
    double LtimesR = pow(L, i) * R;
    double invLR = 1.0 / LtimesR;
    auto yMul_invR = cryptoContext->EvalMult(y, invLR);
    temp_y = B(yMul_invR, cryptoContext);
    y = cryptoContext->EvalMult(temp_y, LtimesR);
  }
  return y;
}


int main() {
    std::cout << "HELLO!" << std::endl;
    // TESTCODE
    uint32_t degree = 246;
    double a = -2048; double b = 2048;    
    
    auto derivative_htan_func = [](double x) -> double {  return (1 - tanh(pow(100*x,2))); };
    auto inverse_func = [](double x) -> double {  return (pow(x,2)/(pow(x,2)+1)); };
    //auto takePower = [](double x) -> double {  return 1-(1-pow(x,30)); };  // 30 is optimal here. Any low or high and the approximation yeilds inaccurate or contaminated results

    std::vector<double> coeffs_htan = EvalChebyshevCoefficients(
        derivative_htan_func, -0.1, 0.1, 56
    );

    std::vector<double> coeffs_inverse = EvalChebyshevCoefficients(
        inverse_func, a, b, degree
    );


    CCParams<CryptoContextCKKSRNS> params;

    ScalingTechnique rescaleTech = FLEXIBLEAUTOEXT;
    usint dcrtBits               = 59;
    usint firstMod               = 60;
    params.SetScalingModSize(dcrtBits);
    params.SetScalingTechnique(rescaleTech);
    params.SetFirstModSize(firstMod);

    params.SetMultiplicativeDepth(41);
    params.SetScalingModSize(45);

    params.SetRingDim(1 << 17);

    std::cout << params << std::endl;

    std::cout << "cc initialzing" << std::endl;
    CryptoContext<DCRTPoly> cc = GenCryptoContext(params);
    std::cout << "cc initialized" << std::endl;
    cc->Enable(PKE);
    cc->Enable(KEYSWITCH);
    cc->Enable(LEVELEDSHE);
    cc->Enable(ADVANCEDSHE);

    int32_t n = cc->GetCryptoParameters()->GetElementParams()->GetCyclotomicOrder() / 2;
    std::vector<int32_t> indexList = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, -n + 2, -n + 3, n - 1, n - 2, -1, -2, -3, -4, -5};

    
    
    std::cout << "p0" << std::endl;
    auto keyPair = cc->KeyGen();
    cc->EvalMultKeyGen(keyPair.secretKey);
    auto pk = keyPair.publicKey;
    cc->EvalRotateKeyGen(keyPair.secretKey, indexList);
    std::cout << "p1" << std::endl;
    std::vector<double> msgVec(cc->GetRingDimension() / 2, 800);

    
    
    std::string filename = "/home/nkoirala/newVAF/data/hashed_chunks.csv";
    std::vector<double> data(65536, 0.0);  // Initialize vector with 65536 elements

    // Read the first 21 numbers from the file
    std::vector<double> chunks = ChunkReader::readChunks(filename);
    
    // Copy first 21 numbers to the beginning of the vector
    size_t nums_to_copy = std::min(chunks.size(), static_cast<size_t>(21));
    for (size_t i = 0; i < nums_to_copy; ++i) {
        data[i] = chunks[i];
    }

    // Fill the remaining elements with random double numbers between 1.0 and 2048.0
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_real_distribution<double> dist(1.0, 2048.0);

    for (size_t i = 21; i < 65536; ++i) {
        data[i] = dist(gen);
    }

    // Print the first few values for verification
    std::cout << "Vector contents (first 30 values):" << std::endl;
    for (size_t i = 0; i < 30; ++i) {
        std::cout << data[i] << " ";
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
    dbPlain = cc->MakeCKKSPackedPlaintext(data);
    dbCipher = cc->Encrypt(dbPlain, pk);

    Plaintext queryPlain; 
    Ciphertext<DCRTPoly> queryCipher;
    queryPlain = cc->MakeCKKSPackedPlaintext(expandedQuery);
    queryCipher = cc->Encrypt(queryPlain, pk);

    auto res1 = cc->EvalSub(queryCipher, dbCipher);

    size_t block_size = 4; // We sum within 7-slot blocks

    for (size_t shift = 1; shift < block_size; ++shift) {
        auto ct_temp = cc->EvalAtIndex(res1, shift);  // Rotate within block
        res1 = cc->EvalAdd(res1, ct_temp);  // Sum rotated values
    }

    auto dep1 = DEP1(2.50, 2048 , 2, res1, cc); // L, R, n, square_inverse, cc);
    // Plaintext decrypted; 
    // cc->Decrypt(keyPair.secretKey, res1, &decrypted);
    // std::vector<double> retVec1 = decrypted->GetRealPackedValue();
    // std::cout << "Results? :" << std::vector<double>(retVec1.begin(), retVec1.begin() + 30) << std::endl;

    


    auto t1 = std::chrono::high_resolution_clock::now();
    // auto square_inverse = EvenChebyshevPS(
    //         cc,
    //         res1,
    //         coeffs_inverse,
    //         a,
    //         b
    //     );

    // auto sender_val = DEP1(2.50, 0.2 , 2, square_inverse, cc); // L, R, n, square_inverse, cc);

    // auto mult = cc->EvalMult(sender_val, 10);

    // auto sender_val2 = DEP1(2.50, 0.1 , 3, mult, cc);

    // // [ -1.34323e-06 0.0100685 0.039897 0.088404 0.23387 0.74321 1.0164 0.959644 1.01011 1.004 ]
    // // DEP 
    // // [ 1.94874e-06 0.00840645 0.000251872 0.00478257 0.00846918 0.00998618 0.00221137 0.00875236 0.00123177 0.00114142 ]

    // auto ret = EvenChebyshevPS(
    //         cc,
    //         sender_val2,
    //         coeffs_htan,
    //         -0.1,
    //         0.1
    //     );
    
    // auto mult2 = cc->EvalMult(ret, 10);
    // cc->EvalSquareInPlace(mult2);
    // auto take_pow = cc->EvalChebyshevFunction(
    //         takePower,
    //         ret,
    //         -1,
    //         1,
    //         27
    //     );

    // auto sub = cc->EvalSub(1, take_pow);
    

    auto t2 = std::chrono::high_resolution_clock::now();
    double timeSec = std::chrono::duration<double>(t2-t1).count();
    std::cout << "DONE!" << std::endl;
    std::cout << "Time (s): " << timeSec << std::endl;

    Plaintext decrypted; 
    cc->Decrypt(keyPair.secretKey, dep1, &decrypted);
    std::vector<double> retVec = decrypted->GetRealPackedValue();
    std::cout << "Results? :" << std::vector<double>(retVec.begin(), retVec.begin() + 30) << std::endl;



    // {
    //     std::cout << "<<< Original PS METHOD >>>" << std::endl;
    //     auto t1 = std::chrono::high_resolution_clock::now();
    //     auto ret = cc->EvalChebyshevFunction(
    //         derivative_htan_func,
    //         x,
    //         a,
    //         b,
    //         degree
    //     );
    //     auto t2 = std::chrono::high_resolution_clock::now();
    //     double timeSec = std::chrono::duration<double>(t2-t1).count();
    //     std::cout << "DONE!" << std::endl;
    //     std::cout << "Time (s): " << timeSec << std::endl;
    //     cc->Decrypt(keyPair.secretKey, ret, &ptxt);
    //     std::vector<double> retVec = ptxt->GetRealPackedValue();
    //     std::cout << "Results? :" << std::vector<double>(retVec.begin(), retVec.begin() + 10) << std::endl;
    // }

    // {
    //     std::cout << "<<< EVEN PS METHOD >>>" << std::endl;
    //     auto t1 = std::chrono::high_resolution_clock::now();
    //     auto ret = EvenChebyshevPS(
    //         cc,
    //         x,
    //         coeffs,
    //         a,
    //         b
    //     );
    //     auto t2 = std::chrono::high_resolution_clock::now();
    //     double timeSec = std::chrono::duration<double>(t2-t1).count();
    //     std::cout << "DONE!" << std::endl;
    //     std::cout << "Time (s): " << timeSec << std::endl;
    //     cc->Decrypt(keyPair.secretKey, ret, &ptxt);
    //     std::vector<double> retVec = ptxt->GetRealPackedValue();
    //     std::cout << "Results? :" << std::vector<double>(retVec.begin(), retVec.begin() + 10) << std::endl;        
    // }

}