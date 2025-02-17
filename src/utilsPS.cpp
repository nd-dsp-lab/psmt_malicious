#include "utilsPS.h"

uint32_t Degree(const std::vector<double>& coefficients) {
    const size_t coefficientsSize = coefficients.size();
    if (!coefficientsSize) {
        OPENFHE_THROW("The coefficients vector can not be empty");
    }

    int32_t indx = coefficientsSize;
    while (--indx >= 0) {
        if (coefficients[indx])
            break;
    }

    // indx becomes negative (-1) only when all coefficients are zeroes. in this case we return 0
    return static_cast<uint32_t>((indx < 0) ? 0 : indx);
}

enum { UPPER_BOUND_PS = 2204 };
std::vector<uint32_t> PopulateParameterPS(const uint32_t upperBoundDegree) {
    std::vector<uint32_t> mlist(upperBoundDegree);

    std::fill(mlist.begin(), mlist.begin() + 2, 1);            // n in [1,2], m = 1
    std::fill(mlist.begin() + 2, mlist.begin() + 11, 2);       // n in [3,11], m = 2
    std::fill(mlist.begin() + 11, mlist.begin() + 13, 3);      // n in [12,13], m = 3
    std::fill(mlist.begin() + 13, mlist.begin() + 17, 2);      // n in [14,17], m = 2
    std::fill(mlist.begin() + 17, mlist.begin() + 55, 3);      // n in [18,55], m = 3
    std::fill(mlist.begin() + 55, mlist.begin() + 59, 4);      // n in [56,59], m = 4
    std::fill(mlist.begin() + 59, mlist.begin() + 76, 3);      // n in [60,76], m = 3
    std::fill(mlist.begin() + 76, mlist.begin() + 239, 4);     // n in [77,239], m = 4
    std::fill(mlist.begin() + 239, mlist.begin() + 247, 5);    // n in [240,247], m = 5
    std::fill(mlist.begin() + 247, mlist.begin() + 284, 4);    // n in [248,284], m = 4
    std::fill(mlist.begin() + 284, mlist.begin() + 991, 5);    // n in [285,991], m = 5
    std::fill(mlist.begin() + 991, mlist.begin() + 1007, 6);   // n in [992,1007], m = 6
    std::fill(mlist.begin() + 1007, mlist.begin() + 1083, 5);  // n in [1008,1083], m = 5
    std::fill(mlist.begin() + 1083, mlist.begin() + 2015, 6);  // n in [1084,2015], m = 6
    std::fill(mlist.begin() + 2015, mlist.begin() + 2031, 7);  // n in [2016,2031], m = 7
    std::fill(mlist.begin() + 2031, mlist.end(), 6);           // n in [2032,2204], m = 6

    return mlist;
}

std::vector<uint32_t> ComputeDegreesPS(const uint32_t n) {
    if (n == 0) {
        OPENFHE_THROW("ComputeDegreesPS: The degree is zero. There is no need to evaluate the polynomial.");
    }

    // index n-1 in the vector corresponds to degree n
    if (n <= UPPER_BOUND_PS) {  // hard-coded values
        static const std::vector<uint32_t> mlist = PopulateParameterPS(UPPER_BOUND_PS);
        uint32_t m                               = mlist[n - 1];
        uint32_t k                               = std::floor(n / ((1 << m) - 1)) + 1;

        return std::vector<uint32_t>{k, m};
    }
    else {  // heuristic for larger degrees
        std::vector<uint32_t> klist;
        std::vector<uint32_t> mlist;
        std::vector<uint32_t> multlist;

        for (uint32_t k = 1; k <= n; k++) {
            for (uint32_t m = 1; m <= std::ceil(log2(n / k) + 1) + 1; m++) {
                if (int32_t(n) - int32_t(k * ((1 << m) - 1)) < 0) {
                    if (std::abs(std::floor(log2(k)) - std::floor(log2(sqrt(n / 2)))) <= 1) {
                        klist.push_back(k);
                        mlist.push_back(m);
                        multlist.push_back(k + 2 * m + (1 << (m - 1)) - 4);
                    }
                }
            }
        }
        uint32_t minIndex = std::min_element(multlist.begin(), multlist.end()) - multlist.begin();

        return std::vector<uint32_t>{klist[minIndex], mlist[minIndex]};
    }
}
