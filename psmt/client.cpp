#include "../psmt/client.h"

Ciphertext<DCRTPoly> encryptQuery(
    CryptoContext<DCRTPoly> cc,
    PublicKey<DCRTPoly> pk,
    uint64_t item,
    uint32_t kappa
) {
    // Chunk the data 
    uint32_t maskLen = 64 / kappa;
    uint32_t mask = ((uint64_t)(1) << maskLen) - 1;

    std::vector<uint64_t> chunkItem(kappa);
    for (uint32_t i = 0; i < kappa; i++) {
        chunkItem[kappa - i - 1] = item & mask;
        item >>= maskLen;
    }

    // Prepare the Query Cipehrtext
    std::vector<double> msgVec(1<<16);
    for (uint32_t i = 0; i < 1<<16; i++) {
        msgVec[i] = chunkItem[i % kappa];
    }
    Plaintext ptxt = cc->MakeCKKSPackedPlaintext(msgVec);
    Ciphertext<DCRTPoly> ret = cc->Encrypt(ptxt, pk);
    return ret;
}