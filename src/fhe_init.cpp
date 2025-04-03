#include "fhe_init.h"
#include <iostream>

using namespace lbcrypto;

FHEContext InitFHE(const FHEParams &params) {
    FHEContext context;
    CCParams<CryptoContextCKKSRNS> cryptoParams;

    //cryptoParams.SetExecutionMode(EXEC_EVALUATION);

    cryptoParams.SetMultiplicativeDepth(params.multiplicativeDepth);
    cryptoParams.SetScalingModSize(params.scalingModSize);
    cryptoParams.SetFirstModSize(params.firstModSize);
    cryptoParams.SetRingDim(params.ringDim);
    
    cryptoParams.SetScalingTechnique(FLEXIBLEAUTOEXT);


    cryptoParams.SetNoiseEstimate(39);  // max. noise is 39 for 64-bit OpenFHE

    cryptoParams.SetDesiredPrecision(25);
    cryptoParams.SetStatisticalSecurity(30);
    cryptoParams.SetNumAdversarialQueries(1);

    cryptoParams.SetDecryptionNoiseMode(NOISE_FLOODING_DECRYPT);
    //cryptoParams.SetThresholdNumOfParties(5);
    
    /*
    // int alpha = 1024;
    // int s = 36;
    // cryptoParams.SetNumAdversarialQueries(alpha);
    // cryptoParams.SetStatisticalSecurity(s);
    //cryptoParams.SetThresholdNumOfParties(ceil(num_parties/2));

    // sigma (noise bits) = underroot(24 * N * alpha) * 2^(s/2), N is the ring-dimension of RLWE
    double noise = 39;  // highest 39 for 64-bit
    cryptoParams.SetNoiseEstimate(noise);
    */
    

    std::cout << "Generating CryptoContext..." << std::endl;
    context.cryptoContext = GenCryptoContext(cryptoParams);

    std::cerr << "\nCKKS parameters :::::::: " << cryptoParams << std::endl;
    context.cryptoContext->Enable(PKE);
    context.cryptoContext->Enable(KEYSWITCH);
    context.cryptoContext->Enable(LEVELEDSHE);
    context.cryptoContext->Enable(ADVANCEDSHE);
    context.cryptoContext->Enable(MULTIPARTY);

    // Generate keys.
    context.keyPair = context.cryptoContext->KeyGen();
    context.cryptoContext->EvalMultKeyGen(context.keyPair.secretKey);

    // Example rotation indices (adjust as needed).
    int32_t n = context.cryptoContext->GetCryptoParameters()->GetElementParams()->GetCyclotomicOrder() / 2;
    std::vector<int32_t> indexList = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, -n + 2, -n + 3, n - 1, n - 2, -1, -2, -3, -4, -5}; // depends on the k-value
    context.cryptoContext->EvalRotateKeyGen(context.keyPair.secretKey, indexList);

    std::cout << cryptoParams << std::endl;

    return context;
}
