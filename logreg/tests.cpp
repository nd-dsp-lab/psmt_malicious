#include "tests.h"

std::vector<double> genDataNormal(
    uint32_t numItems
) {
    std::random_device rd;
    std::mt19937 gen(rd());
    std::normal_distribution<double> dist(0, 1);

    std::vector<double> retVec(numItems);

    #pragma omp parallel for
    for (uint32_t i = 0; i < numItems; i++) {
        retVec[i] = dist(gen);
    }
    return retVec;
}


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
    CancerDB DB = readDatabase("../logreg/data/data.csv");

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