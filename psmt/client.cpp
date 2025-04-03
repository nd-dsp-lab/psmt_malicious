#include "../psmt/client.h"

Ciphertext<DCRTPoly> encryptQuery(
    CryptoContext<DCRTPoly> cc,
    PublicKey<DCRTPoly> pk,
    std::vector<uint64_t> item,
    uint32_t kappa
) {
    // Chunk the data 
    uint32_t maskLen = 64 / kappa;
    uint32_t mask = ((uint64_t)(1) << maskLen) - 1;

    std::vector<uint64_t> chunkItem(kappa);
    uint32_t subKappa = kappa / item.size();

    for (uint32_t i = 0; i < item.size() ; i++) {
        uint64_t currItem = item[i];
        uint32_t offset = subKappa * i;

        for (uint32_t j = 0; j < subKappa; j++) {
            chunkItem[offset + j] = currItem & mask;
            currItem >>= maskLen;
        }
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