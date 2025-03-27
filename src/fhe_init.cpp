#include "fhe_init.h"
#include <iostream>

using namespace lbcrypto;

FHEContext InitFHE(const FHEParams &params) {
    FHEContext context;
    CCParams<CryptoContextCKKSRNS> cryptoParams;

    cryptoParams.SetMultiplicativeDepth(params.multiplicativeDepth);
    cryptoParams.SetScalingModSize(params.scalingModSize);
    cryptoParams.SetFirstModSize(params.firstModSize);
    cryptoParams.SetRingDim(params.ringDim);
    cryptoParams.SetScalingTechnique(FLEXIBLEAUTOEXT);

    cryptoParams.SetMultipartyMode(NOISE_FLOODING_MULTIPARTY);

    std::cout << "Generating CryptoContext..." << std::endl;
    context.cryptoContext = GenCryptoContext(cryptoParams);
    context.cryptoContext->Enable(PKE);
    context.cryptoContext->Enable(KEYSWITCH);
    context.cryptoContext->Enable(LEVELEDSHE);
    context.cryptoContext->Enable(ADVANCEDSHE);

    // Generate keys.
    context.keyPair = context.cryptoContext->KeyGen();
    context.cryptoContext->EvalMultKeyGen(context.keyPair.secretKey);

    // Example rotation indices (adjust as needed).
    int32_t n = context.cryptoContext->GetCryptoParameters()->GetElementParams()->GetCyclotomicOrder() / 2;
    std::vector<int32_t> indexList = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, -n + 2, -n + 3, n - 1, n - 2, -1, -2, -3, -4, -5}; // depends on the k-value
    context.cryptoContext->EvalRotateKeyGen(context.keyPair.secretKey, indexList);

    return context;
}
