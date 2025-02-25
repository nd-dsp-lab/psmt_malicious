#ifndef CHEBYSHEV_CONFIG_H
#define CHEBYSHEV_CONFIG_H

#include <vector>
#include <functional>
#include <cstdint>

namespace ChebyshevConstants {
    // Default Chebyshev approximation parameters.
    static constexpr double HTAN_UPPER_BOUND = 8.5;
    static constexpr double HTAN_LOWER_BOUND = -8.5;
    static constexpr uint32_t DEFAULT_DEGREE_HTAN = 58;

    // Inverse
    static constexpr double INVERSE_UPPER_BOUND = 17;
    static constexpr double INVERSE_LOWER_BOUND = -17;
    static constexpr uint32_t DEFAULT_DEGREE_INVERSE = 246;
}

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

/*  OpenFHE parameters
Input Parameters
==========================
- `ciphertext`: This is the ciphertext we wish to operate on.
- `a`: This is the lower bound of underlying plaintext values we could have.
- `b`: This is the upper bound of underlying plaintext values we could have.
- `degree`: This is the polynomial degree of the Chebyshev approximation. A higher degree gives a more precise estimate, but takes longer to run.

How to Choose Multiplicative Depth
====================================
Each run of EvalChebyshevFunction requires a certain number of multiplications which depends on the input polynomial degree. We give a table below to map polynomial degrees to multiplicative depths.

| Degree        | Multiplicative Depth |
| ------------- |:--------------------:|
| 3-5           | 4                    |
| 6-13          | 5                    |
| 14-27         | 6                    |
| 28-59         | 7                    |
| 60-119        | 8                    |
| 120-247       | 9                    |
| 248-495       | 10                   |
| 496-1007      | 11                   |
| 1008-2031     | 12                   |

Note that if we use a range $(a, b) = (-1, 1),$ the multiplicative depth is 1 less than the depths listed in the table.

*/