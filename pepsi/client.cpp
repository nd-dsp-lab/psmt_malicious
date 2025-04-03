#include "pepsi_client.h"
#include "pepsi_core.h"

PEPSIQuery encryptClientData (
    CryptoContext<DCRTPoly> cc,
    PublicKey<DCRTPoly> pk,
    uint64_t data,
    uint32_t numCtxt,
    uint32_t kVal
) {
    std::vector<int64_t> msgVec = getCW(data, numCtxt, kVal);
    std::vector<Ciphertext<DCRTPoly>> payload(numCtxt);

    for (uint32_t i = 0;  i < numCtxt; i++) {
        std::vector<int64_t> _tmp(cc->GetRingDimension(), msgVec[i]);
        Plaintext __tmp = cc->MakePackedPlaintext(_tmp);
        payload[i] = cc->Encrypt(__tmp, pk);
    }
    return PEPSIQuery {
        payload, numCtxt, kVal
    };
}

bool checkIntResult (
    CryptoContext<DCRTPoly> cc,
    PrivateKey<DCRTPoly> sk,
    Ciphertext<DCRTPoly> resCtxt
) {

    Plaintext ret; cc->Decrypt(resCtxt, sk, &ret);
    std::vector<int64_t> retVec =  ret->GetPackedValue();
    // Check whether there is "1" in the received vector.
    for (uint32_t i = 0; i < cc->GetRingDimension(); i++) {
        if (retVec[i] == 1) {
            return 1;
        }
    }
    return 0;
}