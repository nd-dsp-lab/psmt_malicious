#include "../psmt/tests.h"

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


std::vector<uint64_t> genDataInteger(
    uint32_t numItems
) {
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<uint64_t> dist(1, uint64_t(1)<<63);

    std::vector<uint64_t> retVec(numItems);

    #pragma omp parallel for
    for (uint32_t i = 0; i < numItems; i++) {
        retVec[i] = dist(gen);
    }
    return retVec;
}

void GenerateRotationKeys(CryptoContext<DCRTPoly> cryptoContext,
    PrivateKey<DCRTPoly> secretKey,
    int32_t N) {
    // 1) Compute the next power of 2 (P) >= N
    int32_t P = 1<<16;

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

std::vector<double> evalLogRegPlain(
    std::vector<std::vector<double>> x,
    std::vector<double> weight,
    double bias,
    uint32_t kappa
) {
    uint32_t numItem = x[0].size();
    std::vector<double> retVec(numItem, 0);

    for (uint32_t i = 0; i <numItem; i+=kappa) {
        double _tmp = 0;
        for (uint32_t j = 0; j < x.size(); j++) {
            _tmp += weight[j] * x[j][i];
        }
        _tmp += bias;
        retVec[i] = 1.0 / (1.0 + std::exp(-_tmp));
    }
    return retVec;
}


void testSingleServer() {
    std::cout << "<<< " << "TEST FOR A SINGLE SERVER" << ">>>" << std::endl;
    FHEParams params;
    params.multiplicativeDepth = 35;
    params.ringDim = 1<<17;
    params.scalingModSize = 59;
    params.firstModSize = 60;

    FHEContext ctx = InitFHE(params);
    auto cc = ctx.cryptoContext; 
    auto pk = ctx.keyPair.publicKey;
    auto sk = ctx.keyPair.secretKey;
    GenerateRotationKeys(cc, sk, 1<<17);


    uint32_t numItems = 1<<20;
    uint32_t kappa = 8;

    VAFParams paramsVAF {
        17, 4, 4, 3, 4, 0, true 
    };

    // Setup the Database
    // TODO: 128-bit elements
    std::cout << "Generate Data..." << std::endl;
    // std::vector<uint64_t> idMsgVec = genDataInteger(numItems);
    std::vector<uint64_t> idMsgVec(numItems);
    for (uint32_t i = 0; i <numItems; i++) {
        idMsgVec[i] = i;
    }
    std::vector<double> labMsgVec = genDataNormal(numItems);

    // Construct a Database
    std::cout << "Construct a Database..." << std::endl;
    EncryptedDB DB = constructDB(
        cc, pk,
        idMsgVec, labMsgVec,
        42.0, kappa
    );

    // Make a Query Ciphertext
    std::cout << "Encrypt Query..." << std::endl;
    auto queryCtxt = encryptQuery(
        cc, pk, idMsgVec[0], kappa
    );

    std::cout << "Compute Intersection..." << std::endl;

    auto t1 = std::chrono::high_resolution_clock::now();
    auto interRet = compInter(
        cc, paramsVAF, DB, queryCtxt
    );
    auto t2 = std::chrono::high_resolution_clock::now();
    double tdiff = std::chrono::duration<double>(t2-t1).count();

    std::cout << "Done!" << std::endl;
    std::cout << "Time Elapsed: " << tdiff << std::endl;
    Plaintext retPtxt;
    cc->Decrypt(sk, interRet, &retPtxt);
    std::vector<double> retVec = retPtxt->GetRealPackedValue();

    std::cout << "Output Values (20)" << std::endl;
    std::cout << std::vector<double>(retVec.begin(), retVec.begin() + 20)  << std::endl;
    std::cout << "Actual Label: " << labMsgVec[0] << std::endl;
}


void testLeaderServer() {
    std::cout << "<<< " << "TEST FOR A LEADER SERVER" << ">>>" << std::endl;
    FHEParams params;
    params.multiplicativeDepth = 25;
    params.ringDim = 1<<17;
    params.scalingModSize = 59;
    params.firstModSize = 60;

    FHEContext ctx = InitFHE(params);
    auto cc = ctx.cryptoContext; 
    auto pk = ctx.keyPair.publicKey;
    auto sk = ctx.keyPair.secretKey;
    GenerateRotationKeys(cc, sk, 1<<17);

    // Parameter for VAF
    uint32_t kappa = 8;
    uint32_t numLabels = 32;

    // For Simulation
    // Construct Label Ctxts First 
    std::vector<Ciphertext<DCRTPoly>> ctxts(numLabels);
    std::vector<std::vector<double>> inputVec(numLabels);

    #pragma omp parallel for
    for (uint32_t i = 0; i < numLabels; i++) {
        std::vector<double> _tmp = genDataNormal(1<<16);
        for (uint32_t j = 1; j < 1<<16; j+= kappa) {
            _tmp[j] = 1;
        }    
        inputVec[i] = _tmp;
        auto ptxt = cc->MakeCKKSPackedPlaintext(_tmp);
        ctxts[i] = cc->Encrypt(ptxt, pk);
    }

    // Construct LR params
    std::vector<Ciphertext<DCRTPoly>> weights(numLabels);
    std::vector<double> weightVec = genDataNormal(numLabels + 1);


    for (uint32_t i = 0; i < numLabels; i++) {
        std::vector<double> _tmp(1<<16, weightVec[i]);
        auto ptxt = cc->MakeCKKSPackedPlaintext(_tmp);
        weights[i] = cc->Encrypt(ptxt, pk);
    }
    std::vector<double> biasVec(1<<16, weightVec[numLabels]);
    auto ptxt = cc->MakeCKKSPackedPlaintext(biasVec);
    auto bias = cc->Encrypt(ptxt, pk);

    LogRegParams paramsLR {
        weights, bias,
        507,
        -200, 200
    };
    
    // Parameter for VAF
    VAFParams paramsVAFAgg {
        17, 4, 4, 3, 4, 0, true 
    };
    

    std::cout << "Do Leader Server Operations" << std::endl;

    auto t1 = std::chrono::high_resolution_clock::now();
    auto ret = evalCircuit(
        cc, ctxts, paramsVAFAgg, paramsLR, kappa
    );
    auto t2 = std::chrono::high_resolution_clock::now();
    double tdiff = std::chrono::duration<double>(t2-t1).count();

    std::cout << "Done!" << std::endl;
    std::cout << "Time Elapsed: " << tdiff << std::endl;
    Plaintext retPtxtEval;
    Plaintext retPtxtisInter;
    cc->Decrypt(sk, ret.evalRet, &retPtxtEval);
    cc->Decrypt(sk, ret.isInter, &retPtxtisInter);
    std::vector<double> retEvalVec = retPtxtEval->GetRealPackedValue();
    std::vector<double> retInterVec = retPtxtisInter->GetRealPackedValue();

    std::cout << "Output Values (20)" << std::endl;
    std::cout << std::vector<double>(retEvalVec.begin(), retEvalVec.begin() + 20)  << std::endl;
    std::cout << std::vector<double>(retInterVec.begin(), retInterVec.begin() + 20)  << std::endl;\

    std::cout << "Evaluation Result from Plaintext" << std::endl;
    double biasVal = weightVec[numLabels];
    std::vector<double> retVecPlain = evalLogRegPlain(
        inputVec, weightVec, biasVal, kappa
    );    
    std::cout << std::vector<double>(retVecPlain.begin(), retVecPlain.begin() + 20)  << std::endl;
}