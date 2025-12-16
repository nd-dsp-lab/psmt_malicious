#include "tests.h"

// instantiating the random engine locally for each thread
std::vector<double> genDataNormal(uint32_t numItems) {
    std::vector<double> retVec(numItems);

    // Enter a parallel region first
    #pragma omp parallel 
    {
        // Each thread gets its own seed and generator
        std::random_device rd;
        std::mt19937 gen(rd());
        std::normal_distribution<double> dist(0, 1);

        // Distribute the loop iterations among threads
        #pragma omp for
        for (uint32_t i = 0; i < numItems; i++) {
            retVec[i] = dist(gen);
        }
    }
    return retVec;
}

// // this function is not thread safe
// std::vector<double> genDataNormal(
//     uint32_t numItems
// ) {
//     std::random_device rd;
//     std::mt19937 gen(rd());
//     std::normal_distribution<double> dist(0, 1);

//     std::vector<double> retVec(numItems);

//     #pragma omp parallel for
//     for (uint32_t i = 0; i < numItems; i++) {
//         retVec[i] = dist(gen);
//     }
//     return retVec;
// }

void testLogReg() {
    std::cout << "<<< " << "Logistic Regression TEST" << ">>>" << std::endl;
    FHEParams params;
    params.multiplicativeDepth = 15;
    params.ringDim = 1<<17;
    params.scalingModSize = 35;
    params.firstModSize = 59;

    FHEContext ctx = InitFHE(params);
    auto cc = ctx.cryptoContext; 
    auto pk = ctx.keyPair.publicKey;
    auto sk = ctx.keyPair.secretKey;

    // Read Weight and Bias from Files
    std::cout << "Reading Parameters..." << std::endl;
    std::vector<double> paramVec = readParams("../logreg/params/params.bin");
    std::vector<double> ptWeights(paramVec.begin(), paramVec.end() - 1);
    double ptBias = paramVec[paramVec.size() - 2];


    // Pre-process the weights
    uint32_t degree = 247;
    double a = 10; double b = -10;

    std::cout << "Preparing Parameters..." << std::endl;
    LogRegParams LRParams = constructLRParams(
        cc, pk,
        ptWeights, ptBias, 1<<16, degree, a, b
    );

    // Num of Variables
    uint32_t numVar = ptWeights.size();
    std::vector<Ciphertext<DCRTPoly>> ctxts(numVar);

    // Prepare Ciphertexts
    std::cout << "Preparing Data..." << std::endl;
    #pragma omp parallel for
    for (uint32_t i = 0; i < numVar; i++) {
        std::vector<double> _tmpVec = genDataNormal(1<<16);
        Plaintext ptxt = cc->MakeCKKSPackedPlaintext(_tmpVec);
        ctxts[i] = cc->Encrypt(ptxt, pk);
    }

    // Do Eval
    auto t1 = std::chrono::high_resolution_clock::now();
    auto ret = logRegEval(cc, LRParams, ctxts);
    auto t2 = std::chrono::high_resolution_clock::now();
    auto timeRet = std::chrono::duration<double>(t2-t1).count();

    std::cout << "Evaluation Done!" << std::endl;
    std::cout << "Time for Evaluation: " << timeRet << "s" << std::endl;

    // Decryption!
    Plaintext retPtxt;
    cc->Decrypt(sk, ret, &retPtxt);
    std::vector<double> retVec = retPtxt->GetRealPackedValue();

    std::cout << "Decrpytion Result (top 20 values)" << std::endl;
    std::cout << std::vector<double>(retVec.begin(), retVec.begin() + 20) << std::endl;
}

void testEncryptedInference() {
    std::cout << "<<< " << "Logistic Regression TEST" << ">>>" << std::endl;
    FHEParams params;
    params.multiplicativeDepth = 15;
    params.ringDim = 1<<17;
    params.scalingModSize = 35;
    params.firstModSize = 59;

    FHEContext ctx = InitFHE(params);
    auto cc = ctx.cryptoContext; 
    auto pk = ctx.keyPair.publicKey;
    auto sk = ctx.keyPair.secretKey;

    // Read Weight and Bias from Files
    std::cout << "Reading Parameters..." << std::endl;
    std::vector<double> paramVec = readParams("../logreg/params/params.bin");
    std::vector<double> ptWeights(paramVec.begin(), paramVec.end() - 1);
    double ptBias = paramVec[paramVec.size() - 2];

    std::cout << "Reading Statistics..." << std::endl;
    std::vector<double> statVec = readParams("../logreg/params/stats.bin");
    std::vector<double> meanVec(statVec.begin(), statVec.begin() + statVec.size() / 2);
    std::vector<double> stdVec(statVec.begin() + statVec.size() / 2, statVec.end());

    // Pre-process the weights
    uint32_t degree = 247;
    double a = 30; double b = -30;

    std::cout << "Preparing Parameters..." << std::endl;
    LogRegParams LRParams = constructLRParams(
        cc, pk,
        ptWeights, ptBias, 1<<16, degree, a, b
    );

    // Num of Variables
    uint32_t numVar = ptWeights.size();
    std::vector<Ciphertext<DCRTPoly>> ctxts(numVar);
    
    // Prepare Ciphertexts
    std::cout << "Preparing Data..." << std::endl;

    // Read Database
    RawDataBase DB = readDatabase("../logreg/data/data.csv", "../logreg/data/data.csv");

    #pragma omp parallel for
    for (uint32_t i = 0; i < numVar; i++) {
        std::vector<double> _tmpVec(1<<16, 0);
        for (uint32_t j = 0; j < (1<<16); j++) {
            double val = (DB.payload[j % DB.payload.size()][i] - meanVec[i]) / stdVec[i];
            _tmpVec[j] = val;
        }
        Plaintext ptxt = cc->MakeCKKSPackedPlaintext(_tmpVec);
        ctxts[i] = cc->Encrypt(ptxt, pk);
    }

    // Do Eval
    std::cout << "Start Evaluation..." << std::endl;
    auto t1 = std::chrono::high_resolution_clock::now();
    auto ret = logRegEval(cc, LRParams, ctxts);
    auto t2 = std::chrono::high_resolution_clock::now();
    auto timeRet = std::chrono::duration<double>(t2-t1).count();

    std::cout << "Evaluation Done!" << std::endl;
    std::cout << "Time for Evaluation: " << timeRet << "s" << std::endl;

    // Decryption!
    Plaintext retPtxt;
    cc->Decrypt(sk, ret, &retPtxt);
    std::vector<double> retVec = retPtxt->GetRealPackedValue();

    std::cout << "Decrpytion Result (50 values)" << std::endl;
    std::cout << std::vector<double>(retVec.begin(), retVec.begin() + 50) << std::endl;

    std::cout << "Answer (50 values) "  << std::endl;
    std::cout << std::vector<uint32_t>(DB.answer.begin(), DB.answer.begin() + 50) << std::endl;

}


// Test for Inv Sqrt
void testInvSqrt() {
    std::cout << "<<< " << "Inverse Sqrt TEST" << ">>>" << std::endl;
    FHEParams params;
    params.multiplicativeDepth = 17;
    params.ringDim = 1<<17;
    params.scalingModSize = 50;
    params.firstModSize = 59;

    FHEContext ctx = InitFHE(params);
    auto cc = ctx.cryptoContext; 
    auto pk = ctx.keyPair.publicKey;
    auto sk = ctx.keyPair.secretKey;

    // Prepare Sqrt Values

    double alpha = 10.0;
    double prec = 1e-4;

    std::vector<double> Kvals = makeKVals(alpha, prec);
    std::cout << "REQ Depth?: " << 2 * Kvals.size() << std::endl;

    std::vector<double> msgVec(params.ringDim / 2, 12.0);

    Plaintext _ptxt = cc->MakeCKKSPackedPlaintext(msgVec);
    Ciphertext<DCRTPoly> ctxt = cc->Encrypt(_ptxt, pk);

    auto retCtxt = invSqrt(cc, ctxt, alpha, prec, 20.0);
    Plaintext retPtxt;
    cc->Decrypt(retCtxt, sk, &retPtxt);
    auto retVal = retPtxt->GetRealPackedValue();

    std::cout << std::vector<double>(retVal.begin(), retVal.begin() + 20)
    << std::endl;
}

// We have some issues on this test code...
void testTTest() {
    std::cout << "<<< " << "Inverse Sqrt TEST" << ">>>" << std::endl;
    FHEParams params;
    params.multiplicativeDepth = 20;
    params.ringDim = 1<<17;
    params.scalingModSize = 50;
    params.firstModSize = 59;

    FHEContext ctx = InitFHE(params);
    auto cc = ctx.cryptoContext; 
    auto pk = ctx.keyPair.publicKey;
    auto sk = ctx.keyPair.secretKey;

    std::vector<int32_t> rotIdxs;
    for (int32_t i = 1; i < (int32_t)(params.ringDim); i = i * 2) {
        rotIdxs.push_back(i);
    }

    cc->EvalRotateKeyGen(sk, rotIdxs);

    // Prepare Sqrt Values

    double alpha = 10.0;
    double prec = 0.01;
    double B = 0.02;

    double mu = -0.5;
    uint32_t rotRange = 256;
    std::vector<double> data = genDataNormal(rotRange);

    std::vector<double> msgVec(params.ringDim / 2, 0.0);
    for (uint32_t i = 0; i < rotRange; i++) {
        msgVec[i] = data[i];
    }

    Plaintext _ptxt = cc->MakeCKKSPackedPlaintext(msgVec);
    Ciphertext<DCRTPoly> ctxt = cc->Encrypt(_ptxt, pk);

    // 1. Start Timer
    auto start = std::chrono::high_resolution_clock::now();

    auto retCtxt = oneSampleTTestCompact(
        cc, ctxt, 
        params.ringDim,
        rotRange,
        mu,
        alpha, prec, B
    );

    // 2. Stop Timer
    auto end = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double> elapsed = end - start;

    Plaintext retPtxt;
    cc->Decrypt(retCtxt, sk, &retPtxt);
    auto retVal = retPtxt->GetRealPackedValue()[0]; // Get the first slot only

    // Actual T-Test
    double sum = 0.0;
    for (uint32_t i = 0; i < rotRange; i++) {
        sum += data[i];
    }
    sum = sum / rotRange;
    double std = 0.0;
    for (uint32_t i = 0; i < rotRange; i++) {
        std += std::pow(data[i] - sum, 2.0);
    }
    std = std::pow(std / (rotRange*(rotRange - 1)), 0.5);
    double T = (sum - mu) / std;


    std::cout << "Decrypted Result: " << retVal << std::endl;

    std::cout << "Ground Truth: " << T << std::endl;

    // 3. Calculate Precision (Relative Error)
double error = std::abs(retVal - T); // Absolute Error
double relError = std::abs(error / T); // Relative Error in %

double bitPrecision = 0.0;
if (relError > 1e-20) { 
    bitPrecision = -std::log2(relError);
} else {
    // Handle perfect match (avoid log(0))
    bitPrecision = 52.0; // Max bits for standard double
}

// 4. Print Results
std::cout << std::endl;
std::cout << "------------------------------------------------" << std::endl;
std::cout << "BENCHMARK RESULTS" << std::endl;
std::cout << "------------------------------------------------" << std::endl;
std::cout << "Latency   : " << elapsed.count() << " seconds" << std::endl;
std::cout << "FHE Value : " << retVal << std::endl;
std::cout << "True Value: " << T << std::endl;
std::cout << "Abs Error : " << error << std::endl;
std::cout << "Precision : " << relError * 100.0 << "% error" << std::endl;
std::cout << "Bit Precision: " << bitPrecision << " bits" << std::endl;
std::cout << "------------------------------------------------" << std::endl;
}