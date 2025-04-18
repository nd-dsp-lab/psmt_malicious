#include "dep.h"

// Function to compute B(y) = y + (-4/27) * y^3
Ciphertext<DCRTPoly> ComputeB(const Ciphertext<DCRTPoly> &y, 
                              const CryptoContext<DCRTPoly> &cryptoContext) {
    constexpr double coeff = -4.0 / 27.0;
    auto ySquared = cryptoContext->EvalSquare(y);
    auto coeff_y = cryptoContext->EvalMult(y, coeff);
    auto yCubed = cryptoContext->EvalMult(ySquared, coeff_y);
    return cryptoContext->EvalAdd(y, yCubed);
}

// DEP1 function iteratively applies transformation based on L, R, and n
Ciphertext<DCRTPoly> DEP1(double L, double R, int n, 
                          const Ciphertext<DCRTPoly> &x,
                          const CryptoContext<DCRTPoly> &cryptoContext) {
    auto y = x;
    for (int i = n - 1; i >= 0; --i) {
        double L_R_power = pow(L, i) * R;
        double invL_R = 1.0 / L_R_power;
        auto y_scaled = cryptoContext->EvalMult(y, invL_R);
        auto transformed_y = ComputeB(y_scaled, cryptoContext);
        y = cryptoContext->EvalMult(transformed_y, L_R_power);
    }
    return y;
}


Ciphertext<DCRTPoly> DEP2(double L, double R, int n, double lambd,
    const Ciphertext<DCRTPoly> &x,
    const CryptoContext<DCRTPoly> &cryptoContext) {
    auto y = x;
    Ciphertext<DCRTPoly> _tmp;
    // Depth-Efficient Computation of DEP
    // START
    double invL_R = 1.0 /(pow(L, n-1) * R);
    cryptoContext->EvalMultInPlace(y, invL_R);
    double coeff = pow(27.0/4.0, 0.5) / pow(lambd, 1.5);
        
    // We use computationally efficient version.
    for (int i = n - 1; i >= 0; --i) {
        // Compute Lcy(lambda - y^2)
        // Depth 3 Computation
        _tmp = cryptoContext->EvalSquare(y);
        _tmp = cryptoContext->EvalSub(lambd, _tmp);

        if (i > 0) {            
            cryptoContext->EvalMultInPlace(y, L * coeff);
            } else {
            cryptoContext->EvalMultInPlace(y, R * coeff);
            }
        y = cryptoContext->EvalMult(y, _tmp);        
        }
    return y;
}

// Function to compute sign function: f(x) = (3/2) * x - (1/2) * x^3
Ciphertext<DCRTPoly> signFunc(const Ciphertext<DCRTPoly> &x, 
                              const CryptoContext<DCRTPoly> &cryptoContext) {
    auto tempMult = cryptoContext->EvalMult(1.5, x);
    auto xSquare = cryptoContext->EvalSquare(x);
    auto xCube = cryptoContext->EvalMult(x, xSquare);
    auto half = cryptoContext->EvalMult(0.5, xCube);
    cryptoContext->EvalSubInPlace(tempMult, half);
    return tempMult;
}
