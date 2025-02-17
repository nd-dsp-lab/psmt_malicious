#ifndef VAF_H
#define VAF_H

#include <openfhe.h>

using namespace lbcrypto;

Ciphertext<DCRTPoly> compVAFTriple(
    CryptoContext<DCRTPoly> cc,
    Ciphertext<DCRTPoly> x
);

Ciphertext<DCRTPoly> compVAFQuad(
    CryptoContext<DCRTPoly> cc,
    Ciphertext<DCRTPoly> x
);

Ciphertext<DCRTPoly> cleanse(
    CryptoContext<DCRTPoly> cc,
    Ciphertext<DCRTPoly> x
);

#endif