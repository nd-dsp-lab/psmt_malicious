#ifndef CHEBYSHEV_CONFIG_H
#define CHEBYSHEV_CONFIG_H

#include <vector>
#include <functional>

// Configuration for a Chebyshev approximation.
struct ChebyshevConfig {
    std::function<double(double)> func; // Function to approximate.
    double lowerBound;
    double upperBound;
    uint32_t degree; // Degree or number of coefficients.
};

// Computes Chebyshev coefficients using the configuration.
std::vector<double> ComputeChebyshevCoeffs(const ChebyshevConfig &config);

#endif // CHEBYSHEV_CONFIG_H
