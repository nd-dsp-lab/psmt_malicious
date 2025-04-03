#include "fhe_init_pepsi.h"
#include <iostream>

using namespace lbcrypto;

FHEContext InitFHEBFV(const FHEParamsBFV &params) {
    FHEContext context;
    CCParams<CryptoContextBFVRNS> CCparams;
    CCparams.SetRingDim(params.ringDim);
    CCparams.SetMultiplicativeDepth(params.multiplicativeDepth);
    CCparams.SetPlaintextModulus(params.ptModulus);
    CCparams.SetMultipartyMode(NOISE_FLOODING_MULTIPARTY);
    
    std::cout << "Generating CryptoContext..." << std::endl;
    context.cryptoContext = GenCryptoContext(CCparams);
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

    // std::cout << CCparams << std::endl;

    return context;
}
