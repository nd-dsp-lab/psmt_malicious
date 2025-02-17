#ifndef EVENPS_H
#define EVENPS_H

#include <openfhe.h>

using namespace lbcrypto;

Ciphertext<DCRTPoly> EvenChebyshevPS(
    CryptoContext<DCRTPoly> cc,
    Ciphertext<DCRTPoly> x,
    std::vector<double> coeffs,
    double a,
    double b
);


#endif