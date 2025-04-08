#include "../psmt/tests.h"

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

std::vector<std::vector<double>> genDataVecNormal(
    uint32_t numItems,
    uint32_t itemLen
) {
    std::random_device rd;
    std::mt19937 gen(rd());
    std::normal_distribution<double> dist(0, 1);

    std::vector<std::vector<double>> retVec(numItems);

    #pragma omp parallel for
    for (uint32_t i = 0; i < numItems; i++) {
        std::vector<double> _tmp(itemLen, 0);
        for (uint32_t j = 0; j < itemLen; j++) {
            _tmp[j] = dist(gen);
        }
        retVec[i] = _tmp;
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

    VAFParams paramsVAF;
    paramsVAF.setupVAFParams(64, 8);
    

    // Setup the Database
    // TODO: 128-bit elements
    std::cout << "Generate Data..." << std::endl;
    // std::vector<uint64_t> idMsgVec = genDataInteger(numItems);
    std::vector<std::vector<uint64_t>> idMsgVec(numItems);
    for (uint32_t i = 0; i <numItems; i++) {
        std::vector<uint64_t> _tmp(2, 0);
        for (uint32_t j = 0; j < 2; j++) {
            _tmp[j] = i;
        }
        idMsgVec[i] = _tmp;
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
    auto interRet = compInterDB(
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
    // Manually Initialize
    VAFParams paramsVAFAgg;
    paramsVAFAgg.setupVAFParamfromDomain(64);

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

// It would be super-slow...
void testFullPipelineRealData(
    std::string DBPath, 
    std::string ansPath, 
    std::string paramPath, 
    uint32_t itemLen,
    bool isSim,
    int scalingMod
) {
    std::cout << "<<< " << "TEST A FULL PIPELINE WITH REAL DATA" << ">>>" << std::endl;
    FHEParams params;
    if (itemLen == 1){
        params.multiplicativeDepth = 41;
    }
    else if (itemLen == 2){
        params.multiplicativeDepth = 42;
    }
    params.ringDim = 1<<17;


    params.scalingModSize = scalingMod;
    std::cout << "Scaling mod size (optimum=44) is set to " << params.scalingModSize << std::endl;

    params.firstModSize = 60;

    FHEContext ctx = InitFHE(params);
    auto cc = ctx.cryptoContext; 
    auto pk = ctx.keyPair.publicKey;
    auto sk = ctx.keyPair.secretKey;
    GenerateRotationKeys(cc, sk, 1<<17);

    // Read Weights & Bias
    std::cout << "Reading Parameters..." << std::endl;
    std::vector<double> paramVec = readParams(paramPath);
    std::vector<double> ptWeights(paramVec.begin(), paramVec.end() - 1);
    double ptBias = paramVec[paramVec.size() - 2];    

    LogRegParams paramsLR = constructLRParams(
        cc, pk,
        ptWeights, ptBias, 1<<16, 247, -10, 10
    );
    uint32_t numVar = ptWeights.size();
    std::cout << "Done! Number of Variables: " << numVar << std::endl;

    // Load and Prepare Real Data
    std::cout << "Reading Database..." << std::endl;
    RawDataBase DB = readDatabase(DBPath, ansPath);
    uint32_t numData = DB.idVec.size();
    std::cout << "Done! Number of Items: " << numData << std::endl;

    // Preprocess the Database 
    // To avoid excessive memory overhead for the actual protocol
    if ((!isSim) && (numData > (1<<18))) {
        numData = (1<<18);
        std::cout << "TOO large DB for running the actual protocol... Reduce the size to 2^18" << std::endl;
    }

    std::vector<uint64_t> _idMsgVec = DB.idVec;
    std::vector<uint64_t> answer = DB.answer;
    _idMsgVec.resize(numData);
    answer.resize(numData);
    std::vector<std::vector<double>> labMsgVecs(numVar);

    // Simulating through dummy values
    std::vector<std::vector<uint64_t> > idMsgVec(numData);
    for (uint32_t i = 0; i < numData; i++) {
        std::vector<uint64_t> _tmp(itemLen);
        for (uint32_t j = 0; j < itemLen; j++) {
            _tmp[j] = _idMsgVec[i];
        }
        idMsgVec[i] = _tmp;
    }

    for (uint32_t i = 0; i < numVar; i++) {
        std::vector<double> _tmpVec(numData, 0);
        #pragma omp parallel for
        for (uint32_t j = 0; j < numData; j++) {
            _tmpVec[j] = DB.payload[j][i];
        }
        labMsgVecs[i] = _tmpVec;
    }
            
    // Kappa Parameter
    uint32_t kappa = 8 * itemLen;

    // Parameter for VAFs
    VAFParams paramsVAF;
    paramsVAF.setupVAFParams(64 * itemLen, kappa);

    VAFParams paramsVAFAgg;
    paramsVAFAgg.setupVAFParamfromDomain(64);

    // Pre-definition for simplicity
    LSResponse ret;

    // Do simulation or not.
    if (isSim) {
        std::cout << "SIMulation of the protocol for a single server & leader server" << std::endl;

        // Construct a database for a single sender
        std::cout << "Constructing Databases for the first server..." << std::endl;
        EncryptedDB DBfromFirstServer = constructDB(
            cc, pk, idMsgVec, labMsgVecs[0], 0.0, kappa
        );
        std::cout << "Done!" << std::endl;

        // Prepare Query Ctxt
        std::cout << "Do Query Encryption" << std::endl;
        auto q1 = std::chrono::high_resolution_clock::now();
        Ciphertext<DCRTPoly> queryCtxt = encryptQuery(
            cc, pk, idMsgVec[0], kappa
        );  
        auto q2 = std::chrono::high_resolution_clock::now();
        double qdiff = std::chrono::duration<double>(q2-q1).count();
        std::cout << "Done!" << std::endl;
        std::cout << "Time Elapsed: " << qdiff << std::endl;      

        size_t querySize = ctxtSize(queryCtxt);
        std::cout << "\nQuery Ciphertext Size (R -> S): " << querySize << std::endl;

        // Do Intersection
        std::vector<Ciphertext<DCRTPoly>> interCtxts(numVar);
        std::cout << "Do Local Server Operations" << std::endl;
        auto t1 = std::chrono::high_resolution_clock::now();
        interCtxts[0] = compInterDB(cc, paramsVAF, DBfromFirstServer, queryCtxt);
        auto t2 = std::chrono::high_resolution_clock::now();
        double tdiff = std::chrono::duration<double>(t2-t1).count();
        std::cout << "Done!" << std::endl;
        std::cout << "Time Elapsed: " << tdiff << std::endl;      

        size_t resultSize = ctxtSize(interCtxts[0]);
        std::cout << "\nResult ciphertext Size (Computing Sender, S->L): " << resultSize << std::endl;  

        // DEBUG
        // Plaintext _ptxtDebug;
        // cc->Decrypt(sk, interCtxts[0], &_ptxtDebug);
        // std::vector<double> _retDebug = _ptxtDebug->GetRealPackedValue();

        // std::cout << "[DEBUG] Output of the single sender's output" << std::endl;
        // std::cout << std::vector<double>(_retDebug.begin(), _retDebug.begin() + 40) << std::endl;
        // std::cout << idMsgVec[0] << std::endl;

        uint32_t lvlinterCtxt = interCtxts[0]->GetLevel();

        // Simulating the resulting ciphertexts from other senders        
        std::cout << "Simulating other servers' outputs" << std::endl;
        #pragma omp parallel for
        for (uint32_t i = 1; i < numVar; i++) {
            std::vector<double> mockMsg(1<<16, 0);
            for (uint32_t j = 0; j < (1<<16); j = j + kappa) {
                mockMsg[j] = labMsgVecs[i][0];
                mockMsg[j+1] = 1;
            }
            Plaintext mockPtxt = cc->MakeCKKSPackedPlaintext(mockMsg);
            Ciphertext<DCRTPoly> mockCtxt = cc->Encrypt(mockPtxt, pk);

            for (uint32_t i = 0; i < lvlinterCtxt; i++) {
                cc->Rescale(mockCtxt);
            }
            interCtxts[i] = mockCtxt;
        }
        std::cout << "Done!" << std::endl;

        size_t mockSize = ctxtSize(interCtxts[1]);
        std::cout << "\nResult ciphertext Size (Mock Senders, S->L): " << mockSize << std::endl;  

        // Do Logistic Regression
        std::cout << "Do Leader Server Operations" << std::endl;
        auto t1_ls = std::chrono::high_resolution_clock::now();
        ret = evalCircuit(
            cc, interCtxts, paramsVAFAgg, paramsLR, kappa
        );
        auto t2_ls = std::chrono::high_resolution_clock::now();
        double tdiff_ls = std::chrono::duration<double>(t2_ls-t1_ls).count();
        std::cout << "Done!" << std::endl;
        std::cout << "Time Elapsed: " << tdiff_ls << std::endl;  

        auto answer = ret.evalRet;
        // rescale this answer ciphertext ********
        auto flag = ret.isInter;

        size_t ansSize = ctxtSize(answer);
        size_t flagSize = ctxtSize(flag);
        std::cout << "\nReturn ciphertext size (Answer, Leader sender, L->S): " << ansSize << std::endl;       
        std::cout << "\nReturn ciphertext size (Flag, Leader sender, L->S): " << flagSize << std::endl;        

    } else {
        std::cout << "ACTUAL run of the protocol for ALL servers." << std::endl;

        // Encrypt the database 
        std::cout << "Constructing Databases..." << std::endl;
        std::vector<EncryptedDB> DBfromServers(numVar);
        for (uint32_t i = 0; i < numVar; i++) {
            DBfromServers[i] = constructDB(
                cc, pk,
                idMsgVec, labMsgVecs[i], 0.0, kappa
            );
        }
        std::cout << "Done!" << std::endl;

        // Prepare Query Ctxt
        Ciphertext<DCRTPoly> queryCtxt = encryptQuery(
            cc, pk, idMsgVec[0], kappa
        );

        std::cout << "Do Local Server Operations" << std::endl;

        auto t1 = std::chrono::high_resolution_clock::now();
        std::vector<Ciphertext<DCRTPoly>> interCtxts(numVar);
        for (uint32_t i = 0; i < numVar; i++) {
            interCtxts[i] = compInterDB(
                cc, paramsVAF, DBfromServers[i], queryCtxt
            );
        }    
        auto t2 = std::chrono::high_resolution_clock::now();
        double tdiff = std::chrono::duration<double>(t2-t1).count();

        std::cout << "Done!" << std::endl;
        std::cout << "Time Elapsed (TOTAL): " << tdiff << std::endl;
        std::cout << "Time Elapsed (PER SERVER): " << tdiff / numVar << std::endl;

        std::cout << "Do Leader Server Operations" << std::endl;

        auto t1_ls = std::chrono::high_resolution_clock::now();
        ret = evalCircuit(
            cc, interCtxts, paramsVAFAgg, paramsLR, kappa
        );
        auto t2_ls = std::chrono::high_resolution_clock::now();
        double tdiff_ls = std::chrono::duration<double>(t2_ls-t1_ls).count();
        std::cout << "Done!" << std::endl;
        std::cout << "Time Elapsed: " << tdiff_ls << std::endl;        

    }
    std::cout << "Level of the Eval Ctxt: " << ret.evalRet->GetLevel() << std::endl;
    std::cout << "Level of the Flag Ctxt: " << ret.isInter->GetLevel() << std::endl;

    Plaintext retPtxtEval;
    Plaintext retPtxtisInter;

    std::cout << "Do Result Decryption" << std::endl;
    auto r1 = std::chrono::high_resolution_clock::now();
    cc->Decrypt(sk, ret.evalRet, &retPtxtEval);
    cc->Decrypt(sk, ret.isInter, &retPtxtisInter);
    std::vector<double> retEvalVec = retPtxtEval->GetRealPackedValue();
    std::vector<double> retInterVec = retPtxtisInter->GetRealPackedValue();
    auto r2 = std::chrono::high_resolution_clock::now();
    double rdiff = std::chrono::duration<double>(r2-r1).count();
    std::cout << "Done!" << std::endl;
    std::cout << "Time Elapsed: " << rdiff << std::endl;      

    std::cout << "Output Values (20)" << std::endl;
    std::cout << std::vector<double>(retEvalVec.begin(), retEvalVec.begin() + 20)  << std::endl;
    std::cout << std::vector<double>(retInterVec.begin(), retInterVec.begin() + 20)  << std::endl;

    std::cout << "Evaluation Result from Plaintext" << std::endl;
    std::vector<std::vector<double>> inputVec(numVar);

    for (uint32_t i = 0; i < numVar; i++) {
        std::vector<double> _tmpVec(1<<16, labMsgVecs[i][0]);
        inputVec[i] = _tmpVec;
    }

    std::vector<double> retVecPlain = evalLogRegPlain(
        inputVec, ptWeights, ptBias, kappa
    );    
    std::cout << std::vector<double>(retVecPlain.begin(), retVecPlain.begin() + 20)  << std::endl;
    std::cout << "Correct Answer? " << answer[0] << std::endl;
}


// Full pipeline with Compact label ciphertexts optimization
void testFullPipelineCompactRealData(
    std::string DBPath, 
    std::string ansPath, 
    std::string paramPath, 
    uint32_t itemLen,
    bool isSim,
    int scalingMod
) {
    std::cout << "<<< " << "TEST A FULL PIPELINE WITH REAL DATA (COMPACT OPTIMIZATION)" << " >>>" << std::endl;
    FHEParams params;
    if (itemLen == 1){
        params.multiplicativeDepth = 42;
    }
    else if (itemLen == 2){
        params.multiplicativeDepth = 43;
    }
    params.ringDim = 1<<17;


    params.scalingModSize = scalingMod;
    std::cout << "Scaling mod (optimum=44) size is set to " << params.scalingModSize << std::endl;

    params.firstModSize = 60;

    FHEContext ctx = InitFHE(params);
    auto cc = ctx.cryptoContext; 
    auto pk = ctx.keyPair.publicKey;
    auto sk = ctx.keyPair.secretKey;
    GenerateRotationKeys(cc, sk, 1<<17);

    // Read Weights & Bias
    std::cout << "Reading Parameters..." << std::endl;
    std::vector<double> paramVec = readParams(paramPath);
    std::vector<double> ptWeights(paramVec.begin(), paramVec.end() - 1);
    double ptBias = paramVec[paramVec.size() - 2];    
    uint32_t numVar = ptWeights.size();

    LogRegParamsCompact paramsLR = constructLRParamsCompact(
        cc, pk,
        ptWeights, ptBias, 1<<16, 247, -10, 10
    );
    
    std::cout << "Done! Number of Variables: " << numVar << std::endl;

    // Load and Prepare Real Data
    std::cout << "Reading Database..." << std::endl;
    RawDataBase DB = readDatabase(DBPath, ansPath);
    uint32_t numData = DB.idVec.size();
    std::cout << "Done! Number of Items: " << numData << std::endl;

    // Preprocess the Database 
    // To avoid excessive memory overhead for the actual protocol
    if ((!isSim) && (numData > (1<<18))) {
        numData = (1<<18);
        std::cout << "TOO large DB for running the actual protocol... Reduce the size to 2^18" << std::endl;
    }

    std::vector<uint64_t> _idMsgVec = DB.idVec;
    std::vector<uint64_t> answer = DB.answer;
    _idMsgVec.resize(numData);
    answer.resize(numData);
    std::vector<std::vector<double>> labMsgVecs(numVar);

    // Simulating through dummy values
    std::vector<std::vector<uint64_t> > idMsgVec(numData);
    for (uint32_t i = 0; i < numData; i++) {
        std::vector<uint64_t> _tmp(itemLen);
        for (uint32_t j = 0; j < itemLen; j++) {
            _tmp[j] = _idMsgVec[i];
        }
        idMsgVec[i] = _tmp;
    }

    for (uint32_t i = 0; i < numVar; i++) {
        std::vector<double> _tmpVec(numData, 0);
        #pragma omp parallel for
        for (uint32_t j = 0; j < numData; j++) {
            _tmpVec[j] = DB.payload[j][i];
        }
        labMsgVecs[i] = _tmpVec;
    }
            
    // Kappa Parameter
    uint32_t kappa = 8 * itemLen;

    // Parameter for VAFs
    VAFParams paramsVAF;
    paramsVAF.setupVAFParams(64 * itemLen, kappa);
    
    VAFParams paramsVAFAgg;
    paramsVAFAgg.setupVAFParamfromDomain(64);


    // Pre-definition for simplicity
    LSResponse ret;

    // Do simulation or not.
    if (isSim) {
        std::cout << "SIMulation of the protocol for a single server & leader server" << std::endl;

        // Construct a database for a single sender
        std::cout << "Constructing Databases for the first server..." << std::endl;
        EncryptedDB DBfromFirstServer = constructDB(
            cc, pk, idMsgVec, labMsgVecs[0], 0.0, kappa
        );
        std::cout << "Done!" << std::endl;

        // Prepare Query Ctxt
        std::cout << "Do Query Encryption" << std::endl;
        auto q1 = std::chrono::high_resolution_clock::now();
        Ciphertext<DCRTPoly> queryCtxt = encryptQuery(
            cc, pk, idMsgVec[0], kappa
        );  
        auto q2 = std::chrono::high_resolution_clock::now();
        double qdiff = std::chrono::duration<double>(q2-q1).count();
        std::cout << "Done!" << std::endl;
        std::cout << "Time Elapsed: " << qdiff << std::endl;       

        size_t querySize = ctxtSize(queryCtxt);
        std::cout << "\nQuery Ciphertext Size (R -> S): " << querySize << std::endl;

        // Do Intersection
        std::vector<Ciphertext<DCRTPoly>> interCtxts(numVar);
        std::cout << "Do Local Server Operations" << std::endl;
        auto t1 = std::chrono::high_resolution_clock::now();
        interCtxts[0] = compInterCompactDB(cc, paramsVAF, DBfromFirstServer, queryCtxt, 0, paramsLR.rotRange);
        auto t2 = std::chrono::high_resolution_clock::now();
        double tdiff = std::chrono::duration<double>(t2-t1).count();
        std::cout << "Done!" << std::endl;
        std::cout << "Time Elapsed: " << tdiff << std::endl;     

        size_t resultSize = ctxtSize(interCtxts[0]);
        std::cout << "\nResult ciphertext Size (Computing Sender, S->L): " << resultSize << std::endl;     

        uint32_t lvlinterCtxt = interCtxts[0]->GetLevel();

        // Simulating the resulting ciphertexts from other senders
        std::cout << "Simulating other servers' outputs" << std::endl;

        #pragma omp parallel for
        for (uint32_t i = 1; i < numVar; i++) {
            std::vector<double> mockMsg(1<<16, 0);
            mockMsg[i] = labMsgVecs[i][0];
            mockMsg[paramsLR.rotRange] = 1;
            Plaintext mockPtxt = cc->MakeCKKSPackedPlaintext(mockMsg);
            Ciphertext<DCRTPoly> mockCtxt = cc->Encrypt(mockPtxt, pk);

            for (uint32_t i = 0; i < lvlinterCtxt; i++) {
                cc->Rescale(mockCtxt);
            }

            interCtxts[i] = mockCtxt;
        }
        std::cout << "Done!" << std::endl;

        size_t mockSize = ctxtSize(interCtxts[1]);
        std::cout << "\nResult ciphertext Size (Mock Senders, S->L): " << mockSize << std::endl;

        // Do Logistic Regression
        std::cout << "Do Leader Server Operations" << std::endl;
        auto t1_ls = std::chrono::high_resolution_clock::now();
        ret = evalCircuitCompact(
            cc, interCtxts, paramsVAFAgg, paramsLR, kappa
        );
        auto t2_ls = std::chrono::high_resolution_clock::now();
        double tdiff_ls = std::chrono::duration<double>(t2_ls-t1_ls).count();
        std::cout << "Done!" << std::endl;
        std::cout << "Time Elapsed: " << tdiff_ls << std::endl;    

        auto answer = ret.evalRet;
        auto flag = ret.isInter;

        size_t ansSize = ctxtSize(answer);
        size_t flagSize = ctxtSize(flag);
        std::cout << "\nReturn ciphertext size (Answer, Leader sender, L->S): " << ansSize << std::endl;       
        std::cout << "\nReturn ciphertext size (Flag, Leader sender, L->S): " << flagSize << std::endl;               

    } else {
        std::cout << "ACTUAL run of the protocol for ALL servers." << std::endl;

        // Encrypt the database 
        std::cout << "Constructing Databases..." << std::endl;
        std::vector<EncryptedDB> DBfromServers(numVar);
        for (uint32_t i = 0; i < numVar; i++) {
            DBfromServers[i] = constructDB(
                cc, pk,
                idMsgVec, labMsgVecs[i], 0.0, kappa
            );
        }
        std::cout << "Done!" << std::endl;

        // Prepare Query Ctxt
        Ciphertext<DCRTPoly> queryCtxt = encryptQuery(
            cc, pk, idMsgVec[0], kappa
        );

        std::cout << "Do Local Server Operations" << std::endl;

        auto t1 = std::chrono::high_resolution_clock::now();
        std::vector<Ciphertext<DCRTPoly>> interCtxts(numVar);
        for (uint32_t i = 0; i < numVar; i++) {
            interCtxts[i] = compInterCompactDB(
                cc, paramsVAF, DBfromServers[i], queryCtxt, i, paramsLR.rotRange
            );
        }    
        auto t2 = std::chrono::high_resolution_clock::now();
        double tdiff = std::chrono::duration<double>(t2-t1).count();

        std::cout << "Done!" << std::endl;
        std::cout << "Time Elapsed (TOTAL): " << tdiff << std::endl;
        std::cout << "Time Elapsed (PER SERVER): " << tdiff / numVar << std::endl;

        std::cout << "Do Leader Server Operations" << std::endl;

        auto t1_ls = std::chrono::high_resolution_clock::now();
        ret = evalCircuitCompact(
            cc, interCtxts, paramsVAFAgg, paramsLR, kappa
        );
        auto t2_ls = std::chrono::high_resolution_clock::now();
        double tdiff_ls = std::chrono::duration<double>(t2_ls-t1_ls).count();
        std::cout << "Done!" << std::endl;
        std::cout << "Time Elapsed: " << tdiff_ls << std::endl;        

    }

    std::cout << "Level of the Eval Ctxt: " << ret.evalRet->GetLevel() << std::endl;
    std::cout << "Level of the Flag Ctxt: " << ret.isInter->GetLevel() << std::endl;

    Plaintext retPtxtEval;
    Plaintext retPtxtisInter;

    std::cout << "Do Result Decryption" << std::endl;
    auto r1 = std::chrono::high_resolution_clock::now();
    cc->Decrypt(sk, ret.evalRet, &retPtxtEval);
    cc->Decrypt(sk, ret.isInter, &retPtxtisInter);
    std::vector<double> retEvalVec = retPtxtEval->GetRealPackedValue();
    std::vector<double> retInterVec = retPtxtisInter->GetRealPackedValue();
    auto r2 = std::chrono::high_resolution_clock::now();
    double rdiff = std::chrono::duration<double>(r2-r1).count();
    std::cout << "Done!" << std::endl;
    std::cout << "Time Elapsed: " << rdiff << std::endl;    

    std::cout << "Output Values (20)" << std::endl;
    std::cout << std::vector<double>(retEvalVec.begin(), retEvalVec.begin() + 20)  << std::endl;
    std::cout << std::vector<double>(retInterVec.begin(), retInterVec.begin() + 20)  << std::endl;
    std::cout << "Intersection Flag: " << retInterVec[paramsLR.rotRange] << std::endl;

    std::cout << "Evaluation Result from Plaintext" << std::endl;
    std::vector<std::vector<double>> inputVec(numVar);

    for (uint32_t i = 0; i < numVar; i++) {
        std::vector<double> _tmpVec(1<<16, labMsgVecs[i][0]);
        inputVec[i] = _tmpVec;
    }

    std::vector<double> retVecPlain = evalLogRegPlain(
        inputVec, ptWeights, ptBias, kappa
    );    
    std::cout << std::vector<double>(retVecPlain.begin(), retVecPlain.begin() + 20)  << std::endl;
    std::cout << "Correct Answer? " << answer[0] << std::endl;
}

// It would be super-slow...
void testFullPipelineRealDataChunks(
    std::string DBPath, 
    std::string ansPath, 
    std::string paramPath, 
    uint32_t itemLen,
    bool isSim,
    int scalingMod,
    uint32_t numChunks
) {
    std::cout << "<<< " << "TEST A FULL PIPELINE WITH REAL DATA / Chunking " << ">>>" << std::endl;
    std::cout << "# of ciphertext chunks by each sender: " << numChunks << std::endl;
    FHEParams params;
    if (itemLen == 1){
        params.multiplicativeDepth = 41;
    }
    else if (itemLen == 2){
        params.multiplicativeDepth = 42;
    }
    params.ringDim = 1<<17;

    params.scalingModSize = scalingMod;
    std::cout << "Scaling mod (optimum=44) size is set to " << params.scalingModSize << std::endl;
    
    params.firstModSize = 60;

    FHEContext ctx = InitFHE(params);
    auto cc = ctx.cryptoContext; 
    auto pk = ctx.keyPair.publicKey;
    auto sk = ctx.keyPair.secretKey;
    GenerateRotationKeys(cc, sk, 1<<17);

    // Read Weights & Bias
    std::cout << "Reading Parameters..." << std::endl;
    std::vector<double> paramVec = readParams(paramPath);
    std::vector<double> ptWeights(paramVec.begin(), paramVec.end() - 1);
    double ptBias = paramVec[paramVec.size() - 2];    

    LogRegParams paramsLR = constructLRParams(
        cc, pk,
        ptWeights, ptBias, 1<<16, 247, -10, 10
    );
    uint32_t numVar = ptWeights.size();
    std::cout << "Done! Number of Variables: " << numVar << std::endl;

    // Load and Prepare Real Data
    std::cout << "Reading Database..." << std::endl;
    RawDataBase DB = readDatabase(DBPath, ansPath);
    uint32_t numData = DB.idVec.size();
    std::cout << "Done! Number of Items: " << numData << std::endl;

    // Preprocess the Database 
    // To avoid excessive memory overhead for the actual protocol
    if ((!isSim) && (numData > (1<<18))) {
        numData = (1<<18);
        std::cout << "TOO large DB for running the actual protocol... Reduce the size to 2^18" << std::endl;
    }

    std::vector<uint64_t> _idMsgVec = DB.idVec;
    std::vector<uint64_t> answer = DB.answer;
    _idMsgVec.resize(numData);
    answer.resize(numData);
    std::vector<std::vector<double>> labMsgVecs(numVar);

    // Simulating through dummy values
    std::vector<std::vector<uint64_t> > idMsgVec(numData);
    for (uint32_t i = 0; i < numData; i++) {
        std::vector<uint64_t> _tmp(itemLen);
        for (uint32_t j = 0; j < itemLen; j++) {
            _tmp[j] = _idMsgVec[i];
        }
        idMsgVec[i] = _tmp;
    }

    for (uint32_t i = 0; i < numVar; i++) {
        std::vector<double> _tmpVec(numData, 0);
        #pragma omp parallel for
        for (uint32_t j = 0; j < numData; j++) {
            _tmpVec[j] = DB.payload[j][i];
        }
        labMsgVecs[i] = _tmpVec;
    }
            
    // Kappa Parameter
    uint32_t kappa = 8 * itemLen;

    // Parameter for VAFs
    VAFParams paramsVAF;
    paramsVAF.setupVAFParams(64 * itemLen, kappa);

    VAFParams paramsVAFAgg;
    paramsVAFAgg.setupVAFParamfromDomain(64);

    // Pre-definition for simplicity
    LSResponse ret;
    uint32_t chunkSize = (1<<16) / kappa;
    uint32_t numOfTotalChunks = (numData / chunkSize) + (numData % chunkSize != 0);
    uint32_t numOfSendersforLabel = (numOfTotalChunks / numChunks) + (numOfTotalChunks % numChunks != 0);

    std::cout << "SETUP DONE!" << std::endl;
    std::cout << "Number of Total Chunks: \t\t" << numOfTotalChunks << std::endl;
    std::cout << "Number of Labels: \t\t" << numVar << std::endl;
    std::cout << "Number of Senders: \t\t" << numOfSendersforLabel * numVar << std::endl;


    if (numChunks > numOfTotalChunks) {
        throw std::runtime_error("numChunks cannot be larger than the total number of chunks");
    }
    
    // Do simulation or not.
    if (isSim) {
        std::cout << "SIMulation of the protocol for a single server & leader server" << std::endl;

        // Construct a database for a single sender
        std::cout << "Constructing Databases for the first server..." << std::endl;
        EncryptedDB DBfromFirstServer = constructDB(
            cc, pk, idMsgVec, labMsgVecs[0], 0.0, kappa
        );
        std::cout << "Done!" << std::endl;

        // Prepare Query Ctxt
        std::cout << "Do Query Encryption" << std::endl;
        auto q1 = std::chrono::high_resolution_clock::now();
        Ciphertext<DCRTPoly> queryCtxt = encryptQuery(
            cc, pk, idMsgVec[0], kappa
        );  
        auto q2 = std::chrono::high_resolution_clock::now();
        double qdiff = std::chrono::duration<double>(q2-q1).count();
        std::cout << "Done!" << std::endl;
        std::cout << "Time Elapsed: " << qdiff << std::endl;       

        // Do Intersection
        std::vector<std::vector<Ciphertext<DCRTPoly>>> interCtxts(numVar);
        std::vector<Ciphertext<DCRTPoly>> firstInterCtxts;
        std::vector<EncryptedChunk> chunksForFirstServer(
            DBfromFirstServer.chunks.begin(), DBfromFirstServer.chunks.begin() + numChunks
        );

        std::cout << "Do Local Server Operations" << std::endl;
        auto t1 = std::chrono::high_resolution_clock::now();

        // Local Server takes first chunks
        firstInterCtxts.push_back(compInterChunks(cc, paramsVAF, chunksForFirstServer, queryCtxt));

        auto t2 = std::chrono::high_resolution_clock::now();
        double tdiff = std::chrono::duration<double>(t2-t1).count();
        std::cout << "Done!" << std::endl;
        std::cout << "Time Elapsed: " << tdiff << std::endl;        
        uint32_t lvlinterCtxt = firstInterCtxts[0]->GetLevel();

        // Simulating the resulting ciphertexts from other senders        
        std::cout << "Simulating other servers' outputs" << std::endl;
        std::vector<EncryptedChunk> chunksForRemains(
            DBfromFirstServer.chunks.begin() + numChunks, DBfromFirstServer.chunks.end()
        );

        #pragma omp parallel for num_threads(MAX_NUM_CORES)
        for (uint32_t i = 1; i < numOfSendersforLabel; i++) {
            // Construct Mock Ciphertexts
            std::vector<double> mockMsg(1<<16, 0);
            Plaintext mockPtxt = cc->MakeCKKSPackedPlaintext(mockMsg);
            Ciphertext<DCRTPoly> mockCtxt = cc->Encrypt(mockPtxt, pk);
            for (uint32_t i = 0; i < lvlinterCtxt; i++) {
                cc->Rescale(mockCtxt);
            }

            firstInterCtxts.push_back(mockCtxt);
        }   

        interCtxts[0] = firstInterCtxts;

        #pragma omp parallel for num_threads(MAX_NUM_CORES)
        for (uint32_t i = 1; i < numVar; i++) {
            std::vector<Ciphertext<DCRTPoly>> _tmpVec(numOfSendersforLabel);
            for (uint32_t j = 0; j < numOfSendersforLabel; j++) {
                std::vector<double> mockMsg(1<<16, 0);

                if (j == 0) {
                    for (uint32_t k = 0; k < (1<<16); k = k + kappa) {
                        mockMsg[k] = labMsgVecs[i][0];
                        mockMsg[k+1] = 1;
                    }                    
                }
                Plaintext mockPtxt = cc->MakeCKKSPackedPlaintext(mockMsg);
                Ciphertext<DCRTPoly> mockCtxt = cc->Encrypt(mockPtxt, pk);
                for (uint32_t i = 0; i < lvlinterCtxt; i++) {
                    cc->Rescale(mockCtxt);
                }
                _tmpVec[j] = mockCtxt;
            }
            interCtxts[i] = _tmpVec;
        }
        std::cout << "Done!" << std::endl;

        // Do Logistic Regression
        std::cout << "Do Leader Server Operations" << std::endl;
        auto t1_ls = std::chrono::high_resolution_clock::now();
        ret = evalCircuitfromChunks(
            cc, interCtxts, paramsVAFAgg, paramsLR, kappa
        );
        auto t2_ls = std::chrono::high_resolution_clock::now();
        double tdiff_ls = std::chrono::duration<double>(t2_ls-t1_ls).count();
        std::cout << "Done!" << std::endl;
        std::cout << "Time Elapsed: " << tdiff_ls << std::endl;        

    } else {

        throw std::runtime_error("To be implemented soon!");

        std::cout << "ACTUAL run of the protocol for ALL servers." << std::endl;

        // Encrypt the database 
        std::cout << "Constructing Databases..." << std::endl;
        std::vector<EncryptedDB> DBfromServers(numVar);
        for (uint32_t i = 0; i < numVar; i++) {
            DBfromServers[i] = constructDB(
                cc, pk,
                idMsgVec, labMsgVecs[i], 0.0, kappa
            );
        }
        std::cout << "Done!" << std::endl;

        // Prepare Query Ctxt
        Ciphertext<DCRTPoly> queryCtxt = encryptQuery(
            cc, pk, idMsgVec[0], kappa
        );

        std::cout << "Do Local Server Operations" << std::endl;

        auto t1 = std::chrono::high_resolution_clock::now();
        std::vector<Ciphertext<DCRTPoly>> interCtxts(numVar);
        for (uint32_t i = 0; i < numVar; i++) {
            interCtxts[i] = compInterDB(
                cc, paramsVAF, DBfromServers[i], queryCtxt
            );
        }    
        auto t2 = std::chrono::high_resolution_clock::now();
        double tdiff = std::chrono::duration<double>(t2-t1).count();

        std::cout << "Done!" << std::endl;
        std::cout << "Time Elapsed (TOTAL): " << tdiff << std::endl;
        std::cout << "Time Elapsed (PER SERVER): " << tdiff / numVar << std::endl;

        std::cout << "Do Leader Server Operations" << std::endl;

        auto t1_ls = std::chrono::high_resolution_clock::now();
        ret = evalCircuit(
            cc, interCtxts, paramsVAFAgg, paramsLR, kappa
        );
        auto t2_ls = std::chrono::high_resolution_clock::now();
        double tdiff_ls = std::chrono::duration<double>(t2_ls-t1_ls).count();
        std::cout << "Done!" << std::endl;
        std::cout << "Time Elapsed: " << tdiff_ls << std::endl;        

    }
    std::cout << "Level of the Eval Ctxt: " << ret.evalRet->GetLevel() << std::endl;
    std::cout << "Level of the Flag Ctxt: " << ret.isInter->GetLevel() << std::endl;

    Plaintext retPtxtEval;
    Plaintext retPtxtisInter;

    std::cout << "Do Result Decryption" << std::endl;
    auto r1 = std::chrono::high_resolution_clock::now();
    cc->Decrypt(sk, ret.evalRet, &retPtxtEval);
    cc->Decrypt(sk, ret.isInter, &retPtxtisInter);
    std::vector<double> retEvalVec = retPtxtEval->GetRealPackedValue();
    std::vector<double> retInterVec = retPtxtisInter->GetRealPackedValue();
    auto r2 = std::chrono::high_resolution_clock::now();
    double rdiff = std::chrono::duration<double>(r2-r1).count();
    std::cout << "Done!" << std::endl;
    std::cout << "Time Elapsed: " << rdiff << std::endl;    

    std::cout << "Output Values (20)" << std::endl;
    std::cout << std::vector<double>(retEvalVec.begin(), retEvalVec.begin() + 20)  << std::endl;
    std::cout << std::vector<double>(retInterVec.begin(), retInterVec.begin() + 20)  << std::endl;

    std::cout << "Evaluation Result from Plaintext" << std::endl;
    std::vector<std::vector<double>> inputVec(numVar);

    for (uint32_t i = 0; i < numVar; i++) {
        std::vector<double> _tmpVec(1<<16, labMsgVecs[i][0]);
        inputVec[i] = _tmpVec;
    }

    std::vector<double> retVecPlain = evalLogRegPlain(
        inputVec, ptWeights, ptBias, kappa
    );    
    std::cout << std::vector<double>(retVecPlain.begin(), retVecPlain.begin() + 20)  << std::endl;
    std::cout << "Correct Answer? " << answer[0] << std::endl;
}


// Full pipeline with Compact label ciphertexts optimziation
void testFullPipelineCompactRealDataChunks(
    std::string DBPath, 
    std::string ansPath, 
    std::string paramPath, 
    uint32_t itemLen,
    bool isSim,
    int scalingMod,
    uint32_t numChunks
) {
    std::cout << "<<< " << "TEST A FULL PIPELINE WITH REAL DATA (COMPACT OPTIMIZATION) / Chunking" << " >>>" << std::endl;
    std::cout << "# of ciphertext chunks by each sender: " << numChunks << std::endl;
    FHEParams params;
    params.multiplicativeDepth = 41 + itemLen;
    params.ringDim = 1<<17;
    
    params.scalingModSize = scalingMod;
    std::cout << "Scaling mod (optimum=44) size is set to " << params.scalingModSize << std::endl;
    
    params.firstModSize = 60;

    FHEContext ctx = InitFHE(params);
    auto cc = ctx.cryptoContext; 
    auto pk = ctx.keyPair.publicKey;
    auto sk = ctx.keyPair.secretKey;
    GenerateRotationKeys(cc, sk, 1<<17);

    // Read Weights & Bias
    std::cout << "Reading Parameters..." << std::endl;
    std::vector<double> paramVec = readParams(paramPath);
    std::vector<double> ptWeights(paramVec.begin(), paramVec.end() - 1);
    double ptBias = paramVec[paramVec.size() - 2];    
    uint32_t numVar = ptWeights.size();

    LogRegParamsCompact paramsLR = constructLRParamsCompact(
        cc, pk,
        ptWeights, ptBias, 1<<16, 247, -10, 10
    );
    
    std::cout << "Done! Number of Variables: " << numVar << std::endl;

    // Load and Prepare Real Data
    std::cout << "Reading Database..." << std::endl;
    RawDataBase DB = readDatabase(DBPath, ansPath);
    uint32_t numData = DB.idVec.size();
    std::cout << "Done! Number of Items: " << numData << std::endl;

    // Preprocess the Database 
    // To avoid excessive memory overhead for the actual protocol
    if ((!isSim) && (numData > (1<<18))) {
        numData = (1<<18);
        std::cout << "TOO large DB for running the actual protocol... Reduce the size to 2^18" << std::endl;
    }

    std::vector<uint64_t> _idMsgVec = DB.idVec;
    std::vector<uint64_t> answer = DB.answer;
    _idMsgVec.resize(numData);
    answer.resize(numData);
    std::vector<std::vector<double>> labMsgVecs(numVar);

    // Simulating through dummy values
    std::vector<std::vector<uint64_t> > idMsgVec(numData);
    for (uint32_t i = 0; i < numData; i++) {
        std::vector<uint64_t> _tmp(itemLen);
        for (uint32_t j = 0; j < itemLen; j++) {
            _tmp[j] = _idMsgVec[i];
        }
        idMsgVec[i] = _tmp;
    }


    for (uint32_t i = 0; i < numVar; i++) {
        std::vector<double> _tmpVec(numData, 0);
        #pragma omp parallel for
        for (uint32_t j = 0; j < numData; j++) {
            _tmpVec[j] = DB.payload[j][i];
        }
        labMsgVecs[i] = _tmpVec;
    }
            
    // Kappa Parameter
    uint32_t kappa = 8 * itemLen;

    // Parameter for VAFs
    VAFParams paramsVAF;
    paramsVAF.setupVAFParams(64 * itemLen, kappa);
    
    VAFParams paramsVAFAgg;
    paramsVAFAgg.setupVAFParamfromDomain(64);


    // Pre-definition for simplicity
    LSResponse ret;
    uint32_t chunkSize = (1<<16) / kappa;
    uint32_t numOfTotalChunks = (numData / chunkSize) + (numData % chunkSize != 0);
    uint32_t numOfSendersforLabel = (numOfTotalChunks / numChunks) + (numOfTotalChunks % numChunks != 0);

    std::cout << "SETUP DONE!" << std::endl;
    std::cout << "Number of Total Chunks: \t\t" << numOfTotalChunks << std::endl;
    std::cout << "Number of Labels: \t\t" << numVar << std::endl;
    std::cout << "Number of Senders: \t\t" << numOfSendersforLabel * numVar << std::endl;


    if (numChunks > numOfTotalChunks) {
        throw std::runtime_error("numChunks cannot be larger than the total number of chunks");
    }

    // Do simulation or not.
    if (isSim) {
        std::cout << "SIMulation of the protocol for a single server & leader server" << std::endl;

        // Construct a database for a single sender
        std::cout << "Constructing Databases for the first server..." << std::endl;
        EncryptedDB DBfromFirstServer = constructDB(
            cc, pk, idMsgVec, labMsgVecs[0], 0.0, kappa
        );

        uint32_t numOfTotalCtxts = numChunks * 2;

        std::cout << "Database Size: " << ((double)ctxtSize(DBfromFirstServer.chunks[0].idCtxt) * numOfTotalCtxts)/1000000 << " MB" << std::endl;

        
        std::cout << "Done!" << std::endl;

        // Prepare Query Ctxt
        std::cout << "Do Query Encryption" << std::endl;
        auto q1 = std::chrono::high_resolution_clock::now();
        Ciphertext<DCRTPoly> queryCtxt = encryptQuery(
            cc, pk, idMsgVec[0], kappa
        );  
        auto q2 = std::chrono::high_resolution_clock::now();
        double qdiff = std::chrono::duration<double>(q2-q1).count();
        std::cout << "Done!" << std::endl;
        std::cout << "Time Elapsed: " << qdiff << std::endl;      

        // Do Intersection
        std::vector<std::vector<Ciphertext<DCRTPoly>>> interCtxts(numVar);
        std::vector<Ciphertext<DCRTPoly>> firstInterCtxts;
        std::vector<EncryptedChunk> chunksForFirstServer(
            DBfromFirstServer.chunks.begin(), DBfromFirstServer.chunks.begin() + numChunks
        );

        std::cout << "Do Local Server Operations" << std::endl;
        auto t1 = std::chrono::high_resolution_clock::now();

        // Local Server takes first chunks
        firstInterCtxts.push_back(compInterCompactChunks(cc, paramsVAF, chunksForFirstServer, queryCtxt, 0, paramsLR.rotRange));

        auto t2 = std::chrono::high_resolution_clock::now();
        double tdiff = std::chrono::duration<double>(t2-t1).count();
        std::cout << "Done!" << std::endl;
        std::cout << "Time Elapsed: " << tdiff << std::endl;        
        uint32_t lvlinterCtxt = firstInterCtxts[0]->GetLevel();

        // Simulating the resulting ciphertexts from other senders        
        std::cout << "Simulating other servers' outputs" << std::endl;
        std::vector<EncryptedChunk> chunksForRemains(
            DBfromFirstServer.chunks.begin() + numChunks, DBfromFirstServer.chunks.end()
        );

        for (uint32_t i = 1; i < numOfSendersforLabel; i++) {
            // Construct Mock Ciphertexts
            std::vector<double> mockMsg(1<<16, 0);
            Plaintext mockPtxt = cc->MakeCKKSPackedPlaintext(mockMsg);
            Ciphertext<DCRTPoly> mockCtxt = cc->Encrypt(mockPtxt, pk);
            for (uint32_t i = 0; i < lvlinterCtxt; i++) {
                cc->Rescale(mockCtxt);
            }

            firstInterCtxts.push_back(mockCtxt);
        }   

        interCtxts[0] = firstInterCtxts;

        #pragma omp parallel for num_threads(MAX_NUM_CORES)
        for (uint32_t i = 1; i < numVar; i++) {
            std::vector<Ciphertext<DCRTPoly>> _tmpVec(numOfSendersforLabel);
            for (uint32_t j = 0; j < numOfSendersforLabel; j++) {
                std::vector<double> mockMsg(1<<16, 0);

                if (j == 0) {
                    mockMsg[i] = labMsgVecs[i][0]; 
                    mockMsg[paramsLR.rotRange] = 1;
                }
                Plaintext mockPtxt = cc->MakeCKKSPackedPlaintext(mockMsg);
                Ciphertext<DCRTPoly> mockCtxt = cc->Encrypt(mockPtxt, pk);
                for (uint32_t i = 0; i < lvlinterCtxt; i++) {
                    cc->Rescale(mockCtxt);
                }
                _tmpVec[j] = mockCtxt;
            }
            interCtxts[i] = _tmpVec;
        }
        std::cout << "Done!" << std::endl;

        // Do Logistic Regression
        std::cout << "Do Leader Server Operations" << std::endl;
        auto t1_ls = std::chrono::high_resolution_clock::now();
        ret = evalCircuitCompactfromChunks(
            cc, interCtxts, paramsVAFAgg, paramsLR, kappa
        );
        auto t2_ls = std::chrono::high_resolution_clock::now();
        double tdiff_ls = std::chrono::duration<double>(t2_ls-t1_ls).count();
        std::cout << "Done!" << std::endl;
        std::cout << "Time Elapsed: " << tdiff_ls << std::endl;        

    } else {
        throw std::runtime_error("To be implemented soon!");

        std::cout << "ACTUAL run of the protocol for ALL servers." << std::endl;

        // Encrypt the database 
        std::cout << "Constructing Databases..." << std::endl;
        std::vector<EncryptedDB> DBfromServers(numVar);
        for (uint32_t i = 0; i < numVar; i++) {
            DBfromServers[i] = constructDB(
                cc, pk,
                idMsgVec, labMsgVecs[i], 0.0, kappa
            );
        }
        std::cout << "Done!" << std::endl;

        // Prepare Query Ctxt
        Ciphertext<DCRTPoly> queryCtxt = encryptQuery(
            cc, pk, idMsgVec[0], kappa
        );

        std::cout << "Do Local Server Operations" << std::endl;

        auto t1 = std::chrono::high_resolution_clock::now();
        std::vector<Ciphertext<DCRTPoly>> interCtxts(numVar);
        for (uint32_t i = 0; i < numVar; i++) {
            interCtxts[i] = compInterCompactDB(
                cc, paramsVAF, DBfromServers[i], queryCtxt, i, paramsLR.rotRange
            );
        }    
        auto t2 = std::chrono::high_resolution_clock::now();
        double tdiff = std::chrono::duration<double>(t2-t1).count();

        std::cout << "Done!" << std::endl;
        std::cout << "Time Elapsed (TOTAL): " << tdiff << std::endl;
        std::cout << "Time Elapsed (PER SERVER): " << tdiff / numVar << std::endl;

        std::cout << "Do Leader Server Operations" << std::endl;

        auto t1_ls = std::chrono::high_resolution_clock::now();
        ret = evalCircuitCompact(
            cc, interCtxts, paramsVAFAgg, paramsLR, kappa
        );
        auto t2_ls = std::chrono::high_resolution_clock::now();
        double tdiff_ls = std::chrono::duration<double>(t2_ls-t1_ls).count();
        std::cout << "Done!" << std::endl;
        std::cout << "Time Elapsed: " << tdiff_ls << std::endl;        

    }

    std::cout << "Level of the Eval Ctxt: " << ret.evalRet->GetLevel() << std::endl;
    std::cout << "Level of the Flag Ctxt: " << ret.isInter->GetLevel() << std::endl;

    Plaintext retPtxtEval;
    Plaintext retPtxtisInter;
    
    std::cout << "Do Result Decryption" << std::endl;
    auto r1 = std::chrono::high_resolution_clock::now();
    cc->Decrypt(sk, ret.evalRet, &retPtxtEval);
    cc->Decrypt(sk, ret.isInter, &retPtxtisInter);
    std::vector<double> retEvalVec = retPtxtEval->GetRealPackedValue();
    std::vector<double> retInterVec = retPtxtisInter->GetRealPackedValue();
    auto r2 = std::chrono::high_resolution_clock::now();
    double rdiff = std::chrono::duration<double>(r2-r1).count();
    std::cout << "Done!" << std::endl;
    std::cout << "Time Elapsed: " << rdiff << std::endl;    

    std::cout << "Output Values (20)" << std::endl;
    std::cout << std::vector<double>(retEvalVec.begin(), retEvalVec.begin() + 20)  << std::endl;
    std::cout << std::vector<double>(retInterVec.begin(), retInterVec.begin() + 20)  << std::endl;
    std::cout << "Intersection Flag: " << retInterVec[paramsLR.rotRange] << std::endl;

    std::cout << "Evaluation Result from Plaintext" << std::endl;
    std::vector<std::vector<double>> inputVec(numVar);

    for (uint32_t i = 0; i < numVar; i++) {
        std::vector<double> _tmpVec(1<<16, labMsgVecs[i][0]);
        inputVec[i] = _tmpVec;
    }

    std::vector<double> retVecPlain = evalLogRegPlain(
        inputVec, ptWeights, ptBias, kappa
    );    
    std::cout << std::vector<double>(retVecPlain.begin(), retVecPlain.begin() + 20)  << std::endl;
    std::cout << "Correct Answer? " << answer[0] << std::endl;
}

void testFullPipelineCompactRealDataHorizontalChunks(
    std::string DBPath, 
    std::string ansPath, 
    std::string paramPath, 
    uint32_t itemLen,
    bool isSim,
    uint32_t numChunks
) {
    std::cout << "<<< " << "TEST A FULL PIPELINE WITH REAL DATA (COMPACT OPTIMIZATION) / Horizontal Chunking" << " >>>" << std::endl;
    std::cout << "# of ciphertext chunks by each sender: " << numChunks << std::endl;
    FHEParams params;
    params.multiplicativeDepth = 42;
    params.ringDim = 1<<17;
    params.scalingModSize = 44;
    params.firstModSize = 60;

    FHEContext ctx = InitFHE(params);
    auto cc = ctx.cryptoContext; 
    auto pk = ctx.keyPair.publicKey;
    auto sk = ctx.keyPair.secretKey;
    GenerateRotationKeys(cc, sk, 1<<17);

    // Read Weights & Bias
    std::cout << "Reading Parameters..." << std::endl;
    std::vector<double> paramVec = readParams(paramPath);
    std::vector<double> ptWeights(paramVec.begin(), paramVec.end() - 1);
    double ptBias = paramVec[paramVec.size() - 2];    
    uint32_t numVar = ptWeights.size();

    LogRegParamsCompact paramsLR = constructLRParamsCompact(
        cc, pk,
        ptWeights, ptBias, 1<<16, 247, -10, 10
    );
    
    std::cout << "Done! Number of Variables: " << numVar << std::endl;

    // Load and Prepare Real Data
    std::cout << "Reading Database..." << std::endl;
    RawDataBase DB = readDatabase(DBPath, ansPath);
    uint32_t numData = DB.idVec.size();
    std::cout << "Done! Number of Items: " << numData << std::endl;

    // Preprocess the Database 
    // To avoid excessive memory overhead for the actual protocol
    if ((!isSim) && (numData > (1<<18))) {
        numData = (1<<18);
        std::cout << "TOO large DB for running the actual protocol... Reduce the size to 2^18" << std::endl;
    }

    std::vector<uint64_t> _idMsgVec = DB.idVec;
    std::vector<uint64_t> answer = DB.answer;
    _idMsgVec.resize(numData);
    answer.resize(numData);
    std::vector<std::vector<double>> labMsgVecs(numVar);

    // Simulating through dummy values
    std::vector<std::vector<uint64_t> > idMsgVec(numData);
    for (uint32_t i = 0; i < numData; i++) {
        std::vector<uint64_t> _tmp(itemLen);
        for (uint32_t j = 0; j < itemLen; j++) {
            _tmp[j] = _idMsgVec[i];
        }
        idMsgVec[i] = _tmp;
    }


    for (uint32_t i = 0; i < numVar; i++) {
        std::vector<double> _tmpVec(numData, 0);
        #pragma omp parallel for
        for (uint32_t j = 0; j < numData; j++) {
            _tmpVec[j] = DB.payload[j][i];
        }
        labMsgVecs[i] = _tmpVec;
    }
            
    // Kappa Parameter
    uint32_t kappa = 8 * itemLen;

    // Parameter for VAFs
    VAFParams paramsVAF;
    paramsVAF.setupVAFParams(64 * itemLen, kappa);
    
    VAFParams paramsVAFAgg;
    paramsVAFAgg.setupVAFParamfromDomain(64);


    // Pre-definition for simplicity
    LSResponse ret;
    uint32_t chunkSize = (1<<16) / kappa;
    uint32_t numOfTotalChunks = (numData / chunkSize) + (numData % chunkSize != 0);
    uint32_t numOfSendersforLabel = (numOfTotalChunks / numChunks) + (numOfTotalChunks % numChunks != 0);

    std::cout << "SETUP DONE!" << std::endl;
    std::cout << "Number of Total Chunks: \t\t" << numOfTotalChunks << std::endl;
    std::cout << "Number of Labels: \t\t" << numVar << std::endl;
    std::cout << "Number of Senders: \t\t" << numOfSendersforLabel << std::endl;


    if (numChunks > numOfTotalChunks) {
        throw std::runtime_error("numChunks cannot be larger than the total number of chunks");
    }

    // Do simulation or not.
    if (isSim) {
        std::cout << "SIMulation of the protocol for a single server & leader server" << std::endl;

        // Construct a database for a single sender
        std::cout << "Constructing Databases for the first server..." << std::endl;
        EncryptedHorizontalDB DBfromFirstServer = constructHorizontalDB(
            cc, pk, idMsgVec, labMsgVecs, 0.0, kappa
        );
        std::cout << "Done!" << std::endl;

        // Prepare Query Ctxt
        Ciphertext<DCRTPoly> queryCtxt = encryptQuery(
            cc, pk, idMsgVec[0], kappa
        );  

        // Do Intersection
        std::vector<Ciphertext<DCRTPoly>> interCtxts(numOfTotalChunks);
        std::vector<EncryptedHorizontalChunk> chunksForFirstServer(
            DBfromFirstServer.chunks.begin(), DBfromFirstServer.chunks.begin() + numChunks
        );

        std::cout << "Do Local Server Operations" << std::endl;
        auto t1 = std::chrono::high_resolution_clock::now();

        // Local Server takes first chunks
        interCtxts[0] = compInterCompactHorizontalChunks(cc, paramsVAF, chunksForFirstServer, queryCtxt, 0, paramsLR.rotRange);

        auto t2 = std::chrono::high_resolution_clock::now();
        double tdiff = std::chrono::duration<double>(t2-t1).count();
        std::cout << "Done!" << std::endl;
        std::cout << "Time Elapsed: " << tdiff << std::endl;        
        // uint32_t lvlinterCtxt = interCtxts[0]->GetLevel();

        // Simulating the resulting ciphertexts from other senders        
        std::cout << "Simulating other servers' outputs" << std::endl;

        #pragma omp parallel for 
        for (uint32_t i = 1; i < numOfTotalChunks; i++) {
            std::vector<double> _tmpVec(1<<16, 0.0);
            Plaintext _ptxt = cc->MakeCKKSPackedPlaintext(_tmpVec);
            interCtxts[i] = cc->Encrypt(_ptxt, pk);
        }
        std::cout << "Done!" << std::endl;

        // Do Logistic Regression
        std::cout << "Do Leader Server Operations" << std::endl;
        auto t1_ls = std::chrono::high_resolution_clock::now();
        ret = evalCircuitCompact(
            cc, interCtxts, paramsVAFAgg, paramsLR, kappa
        );
        auto t2_ls = std::chrono::high_resolution_clock::now();
        double tdiff_ls = std::chrono::duration<double>(t2_ls-t1_ls).count();
        std::cout << "Done!" << std::endl;
        std::cout << "Time Elapsed: " << tdiff_ls << std::endl;        

    } else {
        throw std::runtime_error("To be implemented soon!");

        std::cout << "ACTUAL run of the protocol for ALL servers." << std::endl;

        // Encrypt the database 
        std::cout << "Constructing Databases..." << std::endl;
        std::vector<EncryptedDB> DBfromServers(numVar);
        for (uint32_t i = 0; i < numVar; i++) {
            DBfromServers[i] = constructDB(
                cc, pk,
                idMsgVec, labMsgVecs[i], 0.0, kappa
            );
        }
        std::cout << "Done!" << std::endl;

        // Prepare Query Ctxt
        Ciphertext<DCRTPoly> queryCtxt = encryptQuery(
            cc, pk, idMsgVec[0], kappa
        );

        std::cout << "Do Local Server Operations" << std::endl;

        auto t1 = std::chrono::high_resolution_clock::now();
        std::vector<Ciphertext<DCRTPoly>> interCtxts(numVar);
        for (uint32_t i = 0; i < numVar; i++) {
            interCtxts[i] = compInterCompactDB(
                cc, paramsVAF, DBfromServers[i], queryCtxt, i, paramsLR.rotRange
            );
        }    
        auto t2 = std::chrono::high_resolution_clock::now();
        double tdiff = std::chrono::duration<double>(t2-t1).count();

        std::cout << "Done!" << std::endl;
        std::cout << "Time Elapsed (TOTAL): " << tdiff << std::endl;
        std::cout << "Time Elapsed (PER SERVER): " << tdiff / numVar << std::endl;

        std::cout << "Do Leader Server Operations" << std::endl;

        auto t1_ls = std::chrono::high_resolution_clock::now();
        ret = evalCircuitCompact(
            cc, interCtxts, paramsVAFAgg, paramsLR, kappa
        );
        auto t2_ls = std::chrono::high_resolution_clock::now();
        double tdiff_ls = std::chrono::duration<double>(t2_ls-t1_ls).count();
        std::cout << "Done!" << std::endl;
        std::cout << "Time Elapsed: " << tdiff_ls << std::endl;        

    }

    std::cout << "Level of the Eval Ctxt: " << ret.evalRet->GetLevel() << std::endl;
    std::cout << "Level of the Flag Ctxt: " << ret.isInter->GetLevel() << std::endl;

    Plaintext retPtxtEval;
    Plaintext retPtxtisInter;
    cc->Decrypt(sk, ret.evalRet, &retPtxtEval);
    cc->Decrypt(sk, ret.isInter, &retPtxtisInter);
    std::vector<double> retEvalVec = retPtxtEval->GetRealPackedValue();
    std::vector<double> retInterVec = retPtxtisInter->GetRealPackedValue();

    std::cout << "Output Values (20)" << std::endl;
    std::cout << std::vector<double>(retEvalVec.begin(), retEvalVec.begin() + 20)  << std::endl;
    std::cout << std::vector<double>(retInterVec.begin(), retInterVec.begin() + 20)  << std::endl;
    std::cout << "Intersection Flag: " << retInterVec[paramsLR.rotRange] << std::endl;

    std::cout << "Evaluation Result from Plaintext" << std::endl;
    std::vector<std::vector<double>> inputVec(numVar);

    for (uint32_t i = 0; i < numVar; i++) {
        std::vector<double> _tmpVec(1<<16, labMsgVecs[i][0]);
        inputVec[i] = _tmpVec;
    }

    std::vector<double> retVecPlain = evalLogRegPlain(
        inputVec, ptWeights, ptBias, kappa
    );    
    std::cout << std::vector<double>(retVecPlain.begin(), retVecPlain.begin() + 20)  << std::endl;
    std::cout << "Correct Answer? " << answer[0] << std::endl;
}
