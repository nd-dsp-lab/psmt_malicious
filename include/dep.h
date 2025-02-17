#ifndef DEP_H
#define DEP_H

#include "openfhe.h"

using namespace lbcrypto;

// Function to compute B(y) = y + (-4/27) * y^3
Ciphertext<DCRTPoly> ComputeB(const Ciphertext<DCRTPoly> &y, 
                              const CryptoContext<DCRTPoly> &cryptoContext);

// DEP1 function iteratively applies transformation based on L, R, and n
Ciphertext<DCRTPoly> DEP1(double L, double R, int n, 
                          const Ciphertext<DCRTPoly> &x,
                          const CryptoContext<DCRTPoly> &cryptoContext);

// Function to compute sign function: f(x) = (3/2) * x - (1/2) * x^3
Ciphertext<DCRTPoly> signFunc(const Ciphertext<DCRTPoly> &x, 
                              const CryptoContext<DCRTPoly> &cryptoContext);

#endif // DEP_H
