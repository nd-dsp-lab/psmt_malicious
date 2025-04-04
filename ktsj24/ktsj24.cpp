// For Open Sanctions Dataset hashed into 20-bits (false-postive rate = 1)

#include "openfhe.h"
#include <cmath>
#include <ctime>
#include <cassert>

#include <iostream>
#include <vector>
#include <algorithm>
#include <random>

#include <fstream>
#include <sstream>
#include <string>


using namespace lbcrypto;
using namespace std;
using namespace std::chrono;
using measure_typ = std::chrono::milliseconds;

#define MAX_NUM_CORES 48

void EvalFunctionExample();

size_t ctxtSize(Ciphertext<DCRTPoly>& ctxt) {
  size_t size = 0;
  for (auto& element : ctxt->GetElements()) {
    for (auto& subelements : element.GetAllElements()) {
      auto length = subelements.GetLength();
      size += length * sizeof(subelements[0]);
    }
  }
  return size;
};

std::vector<double> readChunks(const std::string& filename) {
        std::ifstream inputFile(filename);
        std::vector<double> chunks;

        if (!inputFile.is_open()) {
            std::cerr << "Error opening file: " << filename << std::endl;
            return chunks;
        }

        std::string line;
        bool firstLine = true;  // Skip header

        while (std::getline(inputFile, line)) {
            if (firstLine) {
                firstLine = false;  // Skip the first row (header)
                continue;
            }

            std::istringstream ss(line);
            double chunk;
            ss >> chunk;  // Convert string to double

            if (ss.fail()) continue;  // Handle any parsing errors

            chunks.push_back(chunk);
        }

        inputFile.close();
        return chunks;
    }

std::vector<double> generateRandomNonZeroValues(int size, double min_val, double max_val) {
    std::vector<double> result;

    if (size <= 0) {
        return result; // Return an empty vector if the size is not positive
    }

    if (min_val >= max_val || min_val >= 0.0 || max_val <= 0.0) {
        return result; // Return an empty vector if the range is invalid or does not contain non-zero values
    }

    std::random_device rd;
    std::mt19937 gen(rd());

    // Set the minimum value of the distribution to be 5 units away from 0 in either direction
    std::uniform_real_distribution<double> dis((min_val > 0.0) ? std::max(5.0, min_val) : std::min(-5.0, min_val),
                                               (max_val < 0.0) ? std::min(-5.0, max_val) : std::max(5.0, max_val));

    result.reserve(size);

    // Fill the vector with random non-zero values excluding the range between -5 and 5
    for (int i = 0; i < size; ++i) {
        double random_val = dis(gen);
        result.push_back(random_val);
    }

    return result;
}


 Ciphertext<DCRTPoly> B(const Ciphertext<DCRTPoly> &y, const CryptoContext<DCRTPoly> &cryptoContext){
   constexpr double coeff = -4.0/27.0;
   auto y2 = cryptoContext->EvalSquare(y);
   auto coeff_y = cryptoContext->EvalMult(y, coeff);
   auto final_y = cryptoContext->EvalMult(y2, coeff_y);

   auto tempC = cryptoContext->EvalAdd(y, final_y);

  return tempC;

 }

Ciphertext<DCRTPoly>
DEP1(const double L, const double R, const int n,
                  const Ciphertext<DCRTPoly> &x,
                  const CryptoContext<DCRTPoly> &cryptoContext) {
   assert(n >= 1);
   //assert(x <= std::pow(L, n)*R and x >= -(std::pow(L,n)*R));

   auto y = x;
   Ciphertext<DCRTPoly> temp_y;
   for (int i=n-1; i>=0; --i){

     double LtimesR = pow(L,i) * R;
     double invLR = 1.0 / LtimesR;
     auto yMul_invR = cryptoContext->EvalMult(y, invLR);
     temp_y = B(yMul_invR, cryptoContext);
     y = cryptoContext->EvalMult(temp_y, LtimesR);

   }

   return y;

}

//     // algorithm 2 has higher number of homomorphic evaluations than algorithm 1 for DEP. We stick to using algorithm 1 for now

// Ciphertext<DCRTPoly>
// DEP2(const double L, const double R, const int n,
//                   const Ciphertext<DCRTPoly> &x,
//                   const CryptoContext<DCRTPoly> &cryptoContext) {
//    assert(n >= 1);
//    //assert(x <= std::pow(L, n)*R and x >= -(std::pow(L,n)*R));
//
//    double y = x;
//
//     for (int i = n - 1; i >= 0; --i) {
//         assert(i >= 0);
//         auto y2 = cryptoContext->EvalSquare(y);
//         auto y3 = cryptoContext->EvalMult(y, y2);
//         auto temp_y = cryptoContext->EvalMult((4.0 / (R * R * 27 * pow(L, 2 * i))), y3);
//         cryptoContext->EvalSubInPlace(y, temp_y);
//     }
//
//     cryptoContext->EvalMultInPlace(y, 1/R);
//
//     y /= R;
//     y += (4.0 / 27.0) * ((L * L * (pow(L, n * 2) - 1)) / ((L * L - 1) * pow(L, 2 * n))) * (pow(y, 3) - pow(y, 5));
//     return P(R * y);
//
//    return y;
//
// }


int main(int argc, char* argv[]) {
    EvalFunctionExample();
    return 0;
}


void EvalFunctionExample() {
    std::cout << "--------------------------------- EVAL DEP CHEBYSHEV FUNCTION ---------------------------------"
              << std::endl;
    CCParams<CryptoContextCKKSRNS> parameters;


    //parameters.SetRingDim(1 << 15);

    double L = 2.59;  //2.598076211;
    int n = 9;
    double R = 200;

    size_t j=2;
    size_t k=3;
    double rho = 2.5;

    uint32_t multDepth = 52; 
    unsigned int poly_approx_deg = 247;  

    double low_bound = -R;
    double high_bound = R;
    size_t slots = 65536;

    parameters.SetSecurityLevel(HEStd_128_classic);
    parameters.SetMultiplicativeDepth(multDepth);
    parameters.SetScalingModSize(45);
    parameters.SetBatchSize(slots);
    
    std::cerr << "\nCKKS parameters :::::::: " << parameters << std::endl;


    CryptoContext<DCRTPoly> cc = GenCryptoContext(parameters);
    cc->Enable(PKE);
    cc->Enable(KEYSWITCH);
    cc->Enable(LEVELEDSHE);
    // We need to enable Advanced SHE to use the Chebyshev approximation.
    cc->Enable(ADVANCEDSHE);

    auto keyPair = cc->KeyGen();
    // We need to generate mult keys to run Chebyshev approximations.
    cc->EvalMultKeyGen(keyPair.secretKey);
    auto pk = keyPair.publicKey;

    unsigned int batchSize = cc->GetEncodingParams()->GetBatchSize();
    std::cout << "batchSize: " << batchSize << std::endl;

    std::cout << "parameters: " << parameters << std::endl;

    std::cout << "Range is +-" << R * std::pow(L, n) << std::endl;

    std::cout << "scaling mod size: " << parameters.GetScalingModSize() << std::endl;
    std::cout << "ring dimension: " << cc->GetRingDimension() << std::endl;
    std::cout << "noise estimate: " << parameters.GetNoiseEstimate() << std::endl;
    std::cout << "multiplicative depth: " << parameters.GetMultiplicativeDepth() << std::endl;
    std::cout << "polynomial approx degree for chebyshev: " << poly_approx_deg << std::endl;

    std::cout << "Noise level: " << parameters.GetNoiseEstimate() << std::endl;

     std::cout << "p = " << cc->GetCryptoParameters()->GetPlaintextModulus() << std::endl;
    std::cout << "n = " << cc->GetCryptoParameters()->GetElementParams()->GetCyclotomicOrder() / 2 << std::endl;
    std::cout << "log2 q = " << log2(cc->GetCryptoParameters()->GetElementParams()->GetModulus().ConvertToDouble())
              << std::endl;


    std::string dbFilename = "../hashed_entity_ids_20.csv";
    std::vector<double> chunks = readChunks(dbFilename);    
    std::cout << "Dataset (first 30 values):" << std::endl;
    for (size_t i = 0; i < 30 && i < chunks.size(); ++i) {
        std::cout << chunks[i] << " ";
    }

    std::cout << std::endl;
    std::cout << "\nSize of database vector: " << chunks.size() << std::endl;
    std::cout << std::endl;

    std::string queryFilename = "../query.csv";

    std::vector<double> query = readChunks(queryFilename);
    if (query.empty()) {
        std::cerr << "Error: Query file is empty or couldn't be read." << std::endl;
    }
    query.resize(1);
    std::vector<double> expandedQuery(slots);
    for (size_t i = 0; i < slots; ++i) {
        expandedQuery[i] = query[i % query.size()];
    }
    std::cout << "Expanded query vector (first 30 values):" << std::endl;
    for (size_t i = 0; i < 30; ++i) {
        std::cout << expandedQuery[i] << " ";
    }
    std::cout << std::endl;

    size_t numCiphertexts = (chunks.size() + slots - 1) / slots; // Calculate required ciphertexts
    std::vector<Ciphertext<DCRTPoly>> encryptedChunks;

    // Define a fallback value to pad out vectors
    double dummyValue = 1000;

     #pragma omp parallel for num_threads(MAX_NUM_CORES)
    for (size_t i = 0; i < numCiphertexts; ++i) {
        size_t startIdx = i * slots;
        size_t endIdx = std::min(startIdx + slots, chunks.size());
        std::vector<double> chunkSegment(chunks.begin() + startIdx, chunks.begin() + endIdx);
        
        // Pad with 255 if this is the last chunk and not fully filled
        if (chunkSegment.size() < slots) {
            chunkSegment.resize(slots, dummyValue);
        }
        
        Plaintext dbPlain = cc->MakeCKKSPackedPlaintext(chunkSegment);
        Ciphertext<DCRTPoly> dbCipher = cc->Encrypt(dbPlain, pk);
        encryptedChunks.push_back(dbCipher);
    }

    Plaintext queryPlain = cc->MakeCKKSPackedPlaintext(expandedQuery);
    Ciphertext<DCRTPoly> queryCipher = cc->Encrypt(queryPlain, pk);

    double cipherSize = ctxtSize(encryptedChunks[0]);

    std::cout << "Query Size: " << ctxtSize(queryCipher)/1000000 << " MB" << std::endl;
    std::cout << "Size of a single DB ciphertext: " << cipherSize/1000000 << " MB " << std::endl;
    std::cout << "Successfully encrypted " << encryptedChunks.size() << " ciphertexts." << std::endl;


    // --- Main Cryptographic Computation -> PSMT ---
    auto overallStart = std::chrono::high_resolution_clock::now();

    #pragma omp parallel for num_threads(MAX_NUM_CORES)
    for (size_t i = 0; i < 6; ++i) {
        encryptedChunks[i] = cc->EvalSub(queryCipher, encryptedChunks[i]);
    }

    auto derivative_htan_func = [](double x) -> double {  return (1 - tanh(pow(10*x,2))); };

    #pragma omp parallel for num_threads(MAX_NUM_CORES)
    for (size_t i = 0; i < 6; ++i) {
        encryptedChunks[i] = DEP1(L, R, n, encryptedChunks[i], cc);
    }

    #pragma omp parallel for num_threads(MAX_NUM_CORES)
    for (size_t i = 0; i < 6; ++i) {
        encryptedChunks[i] = cc->EvalChebyshevFunction(derivative_htan_func, encryptedChunks[i], low_bound, high_bound, poly_approx_deg);
    }

    
    //#pragma omp parallel for num_threads(MAX_NUM_CORES)
    for (size_t m = 0; m < j; m++) {
        for (size_t i = 0; i < 6; ++i) {
        cc->EvalSquareInPlace(encryptedChunks[i]);
        }
    }

    //#pragma omp parallel for num_threads(MAX_NUM_CORES)
    for (size_t i = 0; i < 6; ++i) {
        cc->EvalMultInPlace(encryptedChunks[i], rho);
    }

    //#pragma omp parallel for num_threads(MAX_NUM_CORES)
    for (size_t m = 0; m < k; m++) {
        for (size_t i = 0; i < 6; ++i) {
        cc->EvalSquareInPlace(encryptedChunks[i]);
        }
    }

    auto res = cc->EvalAddMany(encryptedChunks);

    auto overallEnd = std::chrono::high_resolution_clock::now();
    double overallTime = std::chrono::duration<double>(overallEnd - overallStart).count();
    std::cout << "Overall execution time: " << overallTime << " s" << std::endl;
    std::cout << "Level: " << res->GetLevel() << std::endl;

    // --- Decryption and Final Output ---
    Plaintext resultPlain;
    cc->Decrypt(keyPair.secretKey, res, &resultPlain);
    std::vector<double> decryptedValues = resultPlain->GetRealPackedValue();
    std::cout << "Precision: " << resultPlain->GetLogPrecision() << std::endl;

    std::cout << "Decrypted Results (first 20 values): ";
    for (size_t i = 0; i < 20 && i < decryptedValues.size(); ++i) {
        std::cout << decryptedValues[i] << " ";
    }
    std::cout << std::endl;

    double sum = std::accumulate(decryptedValues.begin(), decryptedValues.end(), 0.0);
    std::cout << "Summated value: " << sum << std::endl;

  }
