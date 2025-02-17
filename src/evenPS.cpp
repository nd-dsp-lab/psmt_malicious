#include "evenPS.h"
#include "utilsPS.h"
#include <openfhe.h>

using namespace lbcrypto;


// From Chen, Chilloti, Song 
// This function evaluates f tilde; we need to subtract the final result.
Ciphertext<DCRTPoly> InnerEvenChebyshevPS(
    CryptoContext<DCRTPoly> cc,
    Ciphertext<DCRTPoly> x,
    std::vector<double> coeffs,
    uint32_t k,
    uint32_t m,
    std::vector<Ciphertext<DCRTPoly>> &T,
    std::vector<Ciphertext<DCRTPoly>> &T2
) {
    // Line 4 (f2(x) = Tkm * q(x) + r(x))
    uint32_t k2m2k = 2 * k * (1 << (m-1)) - 2 * k;
    std::vector<double> Tkm(int32_t(k2m2k + 2 * k) + 1, 0.0);
    Tkm.back() = 1;
    auto divqr = LongDivisionChebyshev(coeffs, Tkm);

    // Line 5: Subtract x^k(2^m-1)-1
    std::vector<double> r2 = divqr->r;
    if (int32_t(k2m2k - Degree(divqr->r)) <= 0) {
        r2[int32_t(k2m2k)] -= 1;
        r2.resize(Degree(r2) + 1);
    } else {
        r2.resize(int32_t(k2m2k + 1), 0.0);
        r2.back() = -1;
    }

    // Line 6 (r2(x) = c(x)q(x) + s(x))
    auto divcs = LongDivisionChebyshev(r2, divqr->q);

    // Line 8 First
    std::vector<double> s2 = divcs->r;
    s2.resize(int32_t(k2m2k + 1), 0.0);
    s2.back() = 1;

    // Line 7: Evaluate c(u)
    Ciphertext<DCRTPoly> cu;
    uint32_t dc = Degree(divcs->q);
    bool flag_c = false;

    // dc is always even in our case
    // So we don't need to handle the case when dc==1
    if (dc >= 1) {
        std::vector<Ciphertext<DCRTPoly>> ctxs(dc / 2);
        std::vector<double> weights(dc / 2);

        // Always Even!
        // T Contains elements with stride 1
        // q Contains elements with stride 2; we need to multiply 2
        for (uint32_t i = 0; i < dc / 2; i++) {
            ctxs[i] = T[i];
            weights[i] = divcs->q[2*i+2];
        }
        cu = cc->EvalLinearWSumMutable(ctxs, weights);

        // Add the constant term
        cc->EvalAddInPlace(cu, divcs->q.front() / 2);

        // Level Reduce
        usint levelDiff = T2[m-1]->GetLevel() - cu->GetLevel();
        cc->LevelReduceInPlace(cu, nullptr, levelDiff);
        flag_c = true;
    }

    // Line 9: Evqlaute q(u) & s2(u)
    // Compute q(u) first
    Ciphertext<DCRTPoly> qu;
    if (Degree(divqr->q) > 2*k) {
        // More degree? Do recursively.
        qu = InnerEvenChebyshevPS(cc, x, divqr->q, k, m-1, T, T2);
    } else {
        // If not, then we can hande this by ourself!
        auto qcopy = divqr->q;
        // Drop the last term (optimization)
        qcopy.resize(2*k);
        if (Degree(qcopy) > 0) {
            std::vector<Ciphertext<DCRTPoly>> ctxs(Degree(qcopy) / 2);
            std::vector<double> weights(Degree(qcopy) / 2);

            // Always Even!
            for (uint32_t i = 0; i < Degree(qcopy) / 2; i++) {
                ctxs[i] = T[i];
                weights[i] = divqr->q[2*i + 2];
            }
            
            qu = cc->EvalLinearWSumMutable(ctxs, weights);
            Ciphertext<DCRTPoly> sum = T[k-1]->Clone();            
            for (uint32_t i = 0; i < log2(divqr->q.back()); i++) {
                sum = cc->EvalAdd(sum, sum);
            }
            cc->EvalAddInPlace(qu, sum);
        } else {
            Ciphertext<DCRTPoly> sum = T[k-1]->Clone();
            for (uint32_t i = 0; i < log2(divqr->q.back()); i++) {
                sum = cc->EvalAdd(sum, sum);
            }
            qu = sum;
        }

        // Coeffient Term.
        cc->EvalAddInPlace(qu, divqr->q.front() / 2);
    }

    // Compute s2(u)
    Ciphertext<DCRTPoly> su;
    if (Degree(s2) > 2*k) {
        su = InnerEvenChebyshevPS(cc, x, s2, k, m - 1, T, T2);
    } else {
        auto scopy = s2;
        scopy.resize(2*k);

        if (Degree(scopy) > 0) {
            std::vector<Ciphertext<DCRTPoly>> ctxs(Degree(scopy) / 2);
            std::vector<double> weights(Degree(scopy) / 2);

            for (uint32_t i = 0; i < Degree(scopy) / 2; i++) {
                ctxs[i] = T[i];
                weights[i] = s2[2*i+2];
            }

            su = cc->EvalLinearWSumMutable(ctxs, weights);
            // Always Monic!
            cc->EvalAddInPlace(su, T[k-1]);
        } else {
            su = T[k-1]->Clone();
        }

        // Constant Term
        cc->EvalAddInPlace(su, s2.front() / 2);

        // Level Setting
        cc->LevelReduceInPlace(su, nullptr);
    }

    // Line 10: Finalize
    Ciphertext<DCRTPoly> result;

    if (flag_c) {
        result = cc->EvalAdd(T2[m-1], cu);
    } else {
        // C becomes constant, in this case
        result = cc->EvalAdd(T2[m-1], divcs->q.front() / 2);
    }
    // f(u) = (u^k(2^m-1) + c(u))q(u) + s2(u)
    result = cc->EvalMult(result, qu);
    cc->ModReduceInPlace(result);
    cc->EvalAddInPlace(result, su);
    return result;
}

// From Chen, Chilloti, Song 
Ciphertext<DCRTPoly> EvenChebyshevPS(
    CryptoContext<DCRTPoly> cc,
    Ciphertext<DCRTPoly> x,
    std::vector<double> coeffs,
    double a,
    double b
) {
    uint32_t n = Degree(coeffs);
    std::vector<double> f2 = coeffs;

    if (n % 2 != 0) {
        throw std::runtime_error("degree should be even...!");
    }

    if (coeffs[coeffs.size() - 1] == 0) {
        f2.resize(n+1);
    }

    // Line 1
    std::vector<uint32_t> degs = ComputeDegreesPS(n / 2);
    uint32_t k = degs[0];
    uint32_t m = degs[1];

    // Line 3: Compute Basis
    // Table
    std::vector<Ciphertext<DCRTPoly>> T(k);

    // Preparation
    if ((std::round(a) == -1) && (std::round(b) == 1)) {
        T[0] = x->Clone();
    } else {
        double alpha = 2 / (b - a); 
        double beta = 2 * a / (b - a);
        T[0] = cc->EvalMult(x, alpha);
        cc->ModReduceInPlace(T[0]);
        cc->EvalAddInPlace(T[0], -1.0 - beta);
    }

    // First Update
    auto square = cc->EvalSquare(T[0]);
    T[0] = cc->EvalAdd(square, square);
    cc->ModReduceInPlace(T[0]);
    cc->EvalAddInPlace(T[0], -1.0);

    // T_2, T_4, ... T_2k
    for (uint32_t i = 2; i <= k; i+=1) {
        // if i is a power of two
        if (!(i & (i-1))) {
            auto square = cc->EvalSquare(T[i/2 - 1]);
            T[i-1] = cc->EvalAdd(square, square);
            cc->ModReduceInPlace(T[i-1]);
            cc->EvalAddInPlace(T[i-1], -1.0);
        } else {
            // non-power of 2
            if (i % 2 == 1) {
                // i is odd
                // Use relationship: 2 * T_m * T_n = T_{m+n} + T_{m-n}
                auto prod = cc->EvalMult(T[i/2 - 1], T[i/2]);
                T[i-1] = cc->EvalAdd(prod, prod);
                cc->ModReduceInPlace(T[i-1]);
                cc->EvalSubInPlace(T[i-1], T[0]);
            } else {
                auto square = cc->EvalSquare(T[i/2 - 1]);
                T[i-1] = cc->EvalAdd(square, square);
                cc->ModReduceInPlace(T[i-1]);
                cc->EvalAddInPlace(T[i-1], -1.0);
            }

        }
    }

    const auto params = std::dynamic_pointer_cast<CryptoParametersCKKSRNS>(T[k-1]->GetCryptoParameters());

    auto algo = cc->GetScheme();

    if (params->GetScalingTechnique() == FIXEDMANUAL) {
        for (size_t i = 1; i < k; i++) {
            usint levelDiff = T[k-1]->GetLevel() - T[i-1]->GetLevel();
            cc->LevelReduceInPlace(T[i-1], nullptr, levelDiff);
        }
    } else {
        for (size_t i = 1; i < k; i++) {
            algo->AdjustLevelsAndDepthInPlace(T[i-1], T[k-1]);
        }
    }

    // For T2
    // T_2k, T_4k, ..., T_2^m+1k 
    std::vector<Ciphertext<DCRTPoly>> T2(m);
    T2.front() = T.back();
    for (uint32_t i = 1; i < m; i++) {
        auto square = cc->EvalSquare(T2[i-1]);
        T2[i] = cc->EvalAdd(square, square);
        cc->ModReduceInPlace(T2[i]);
        cc->EvalAddInPlace(T2[i], -1.0);
    }

    // T_{2k(2*m - 1)}
    auto T2km1 = T2.front();
    for (uint32_t i = 1; i < m; i++) {
        auto prod = cc->EvalMult(T2km1, T2[i]);
        T2km1 = cc->EvalAdd(prod, prod);
        cc->ModReduceInPlace(T2km1);
        cc->EvalSubInPlace(T2km1, T2.front());
    }

    // Useful Constant
    uint32_t k2m2k = 2 * k * (1<<(m-1)) - 2 * k;

    // Line 2: Add Term
    f2.resize(2 * k2m2k + 2*k + 1, 0.0);
    f2.back() = 1;

    // Line 4
    std::vector<double> Tkm(int32_t(k2m2k + 2*k) + 1, 0.0);
    Tkm.back() = 1;
    auto divqr = LongDivisionChebyshev(f2, Tkm);

    // Line 5.
    std::vector<double> r2 = divqr->r;
    if (int32_t(k2m2k - Degree(divqr->r)) <= 0) {
        r2[int32_t(k2m2k)] -= 1;
        r2.resize(Degree(r2) + 1);
    } else {
        r2.resize(int32_t(k2m2k + 1), 0.0);
        r2.back() = -1;
    }

    // Line 6
    auto divcs = LongDivisionChebyshev(r2, divqr->q);

    // Line 8 First
    std::vector<double> s2 = divcs->r;
    s2.resize(int32_t(k2m2k + 1), 0.0);
    s2.back() = 1;

    // Line 7.
    Ciphertext<DCRTPoly> cu;
    uint32_t dc = Degree(divcs -> q);
    bool flag_c = false;
    if (dc >= 1) {
        std::vector<Ciphertext<DCRTPoly>> ctxs(dc / 2);
        std::vector<double> weights(dc / 2);

        for (uint32_t i = 0; i < dc / 2; i++) {
            ctxs[i] = T[i];
            weights[i] = divcs->q[2*i+2];
        }

        cu = cc->EvalLinearWSumMutable(ctxs, weights);
        cc->EvalAddInPlace(cu, divcs->q.front()/2);
        flag_c = true;
    }

    // Step 9.
    // Compute q(u) first
    Ciphertext<DCRTPoly> qu;

    if (Degree(divqr->q) > 2 * k) {
        qu = InnerEvenChebyshevPS(cc, x, divqr->q, k, m - 1, T, T2);
    } else{
        auto qcopy = divqr->q;
        qcopy.resize(2 * k);
        if (Degree(qcopy) > 0) {
            std::vector<Ciphertext<DCRTPoly>> ctxs(Degree(qcopy) / 2);
            std::vector<double> weights(Degree(qcopy)/ 2);

            for (uint32_t i = 0; i < Degree(qcopy) / 2; i++) {
                ctxs[i] = T[i];
                weights[i] = divqr->q[2 * i + 2];
            }

            qu = cc->EvalLinearWSumMutable(ctxs, weights);
            // Highest order coeff will always be 2.
            Ciphertext<DCRTPoly> sum = cc->EvalAdd(T[k-1], T[k-1]);
            cc->EvalAddInPlace(qu, sum);
        } else {
            qu = T[k-1]->Clone();

            for (uint32_t i = 1; i < divqr -> q.back(); i++) {
                cc->EvalAddInPlace(qu, T[k-1]);
            }
        }

        cc->EvalAddInPlace(qu, divqr->q.front() / 2);
    }

    // Compute s(u)
    Ciphertext<DCRTPoly> su;

    if (Degree(s2) > 2 * k) {
        su = InnerEvenChebyshevPS(cc, x, s2, k, m-1, T, T2);
    } else {
        auto scopy = s2;
        if (Degree(scopy) > 0) {
            std::vector<Ciphertext<DCRTPoly>> ctxs(Degree(scopy) / 2);
            std::vector<double> weights(Degree(scopy) / 2);

            for (uint32_t i = 0; i < Degree(scopy) / 2; i++) {
                ctxs[i] = T[i];
                weights[i] = s2[2*i+2];
            }

            su = cc->EvalLinearWSumMutable(ctxs, weights);
            cc->EvalAddInPlace(su, T[k-1]);
        } else {
            su = T[k-1];
        }

        cc->EvalAddInPlace(su, s2.front() / 2);
    }


    // Line 10
    Ciphertext<DCRTPoly> result;

    if (flag_c) {
        result = cc->EvalAdd(T2[m-1], cu);
    } else {
        result = cc->EvalAdd(T2[m-1], divcs->q.front() / 2);
    }

    result = cc->EvalMult(result, qu);
    cc->ModReduceInPlace(result);
    cc->EvalAddInPlace(result, su);

    // Line 12 (Line 11 was already done!)
    cc->EvalSubInPlace(result, T2km1);

    return result;

}
