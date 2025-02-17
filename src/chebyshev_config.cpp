#include "chebyshev_config.h"
#include "math/chebyshev.h" // Assumes EvalChebyshevCoefficients is defined here.
#include <iostream>
#include "evenPS.h"


std::vector<double> ComputeChebyshevCoeffs(const ChebyshevConfig &config) {
    // Use the provided function and parameters to compute coefficients.
    std::vector<double> coeffs = EvalChebyshevCoefficients(
        config.func, config.lowerBound, config.upperBound, config.degree
    );
    return coeffs;
}
