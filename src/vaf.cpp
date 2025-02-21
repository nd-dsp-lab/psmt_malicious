#include "vaf.h"

using namespace lbcrypto;

// (3x -1)^2 = 9x² -6x +1 -> the depth usage is similar, but the number of operations is reduced.
Ciphertext<DCRTPoly> compVAFTriple(
    CryptoContext<DCRTPoly> cc,
    Ciphertext<DCRTPoly> x
)
{
    
    Ciphertext<DCRTPoly> _tmp;
    auto ret = x->Clone();

    // 3x - 1
    _tmp = cc->EvalAdd(ret, ret);
    cc->EvalAddInPlace(ret, _tmp);
    cc->EvalAddInPlace(ret, -1.0);
    cc->EvalSquareInPlace(ret);

    // 3x - 4
    _tmp = cc->EvalAdd(ret, ret);
    cc->EvalAddInPlace(ret, _tmp);
    cc->EvalAddInPlace(ret, -4.0);
    cc->EvalSquareInPlace(ret);

    // 3x - 64
    _tmp = cc->EvalAdd(ret, ret);
    cc->EvalAddInPlace(ret, _tmp);
    cc->EvalAddInPlace(ret, -64.0);    

    // Divide by 128
    cc->EvalMultInPlace(ret, 0.0078125);
    cc->EvalSquareInPlace(ret);
    return ret;
    

    // auto ret = x->Clone();

    // // Stage 1: (3x - 1)^2 = 9x² -6x +1
    // std::vector<double> coeff1 {1.0, -6.0, 9.0};
    // ret = cc->EvalPoly(ret, coeff1);

    // // Stage 2: (3y -4)^2 = 9y² -24y +16 (y = previous result)
    // std::vector<double> coeff2 {16.0, -24.0, 9.0};
    // ret = cc->EvalPoly(ret, coeff2);

    // // Stage 3: ((3z -64)/128)^2 = (9z² -384z +4096)/16384
    // std::vector<double> coeff3 {
    //     4096.0/16384,  // = 0.25
    //     -384.0/16384, // = -0.0234375
    //     9.0/16384      // ≈ 0.0005493
    // };
    // ret = cc->EvalPoly(ret, coeff3);

    // return ret;

}

Ciphertext<DCRTPoly> compVAFQuad(
    CryptoContext<DCRTPoly> cc,
    Ciphertext<DCRTPoly> x
)
{
    
    Ciphertext<DCRTPoly> _tmp;
    auto ret = x->Clone();

    // 3x - 1
    _tmp = cc->EvalAdd(ret, ret);
    cc->EvalAddInPlace(ret, _tmp);
    cc->EvalAddInPlace(ret, -1.0);
    cc->EvalSquareInPlace(ret);

    // 3x - 4
    _tmp = cc->EvalAdd(ret, ret);
    cc->EvalAddInPlace(ret, _tmp);
    cc->EvalAddInPlace(ret, -4.0);
    cc->EvalSquareInPlace(ret);

    // 3x - 64
    _tmp = cc->EvalAdd(ret, ret);
    cc->EvalAddInPlace(ret, _tmp);
    cc->EvalAddInPlace(ret, -64.0);    
    cc->EvalSquareInPlace(ret);

    // 3x - 16384
    _tmp = cc->EvalAdd(ret, ret);
    cc->EvalAddInPlace(ret, _tmp);
    cc->EvalAddInPlace(ret, -16384.0);    

    // Divide by 32768
    cc->EvalMultInPlace(ret, 0.000030517578125);
    cc->EvalSquareInPlace(ret);
    return ret;
    

    // auto ret = x->Clone();

    // // Stage 1: (3x - 1)^2 = 9x² -6x +1
    // std::vector<double> coeff1 {1.0, -6.0, 9.0};
    // ret = cc->EvalPoly(ret, coeff1);

    // // Stage 2: (3y -4)^2 = 9y² -24y +16 (y = previous result)
    // std::vector<double> coeff2 {16.0, -24.0, 9.0};
    // ret = cc->EvalPoly(ret, coeff2);

    // // Stage 3: ((3z -64)/128)^2 = (9z² -384z +4096)/16384
    // std::vector<double> coeff3 {
    //     4096.0/16384,  // = 0.25
    //     -384.0/16384, // = -0.0234375
    //     9.0/16384      // ≈ 0.0005493
    // };
    // ret = cc->EvalPoly(ret, coeff3);

    // // Stage 4: ((3w -16384)/32768)^2 
    // // = (9w² -98304w +268435456)/1073741824
    // std::vector<double> coeff4 {
    //     268435456.0/1073741824.0,  // = 0.25
    //     -98304.0/1073741824.0,     // ≈ -0.00009155
    //     9.0/1073741824.0           // ≈ 8.38e-09
    // };
    // ret = cc->EvalPoly(ret, coeff4);

    // return ret;
}

// -1/2 * x^3 + 3/2 * x
// Ciphertext<DCRTPoly> sign(
//     CryptoContext<DCRTPoly> cc,
//     Ciphertext<DCRTPoly> x
// ) {
//     // 1/2 * (3 - x^2)
//     Ciphertext<DCRTPoly> _tmp;
//     auto ret = x->Clone();
// }


// -2x^3 + 3x^2
// x^2(3 - 2x) -> total 2 multiplications, depth 2.

Ciphertext<DCRTPoly> cleanse(
    CryptoContext<DCRTPoly> cc,
    Ciphertext<DCRTPoly> x
) {
    Ciphertext<DCRTPoly> _tmp;
    auto ret = x->Clone();
    _tmp = cc->EvalSquare(ret);
    cc->EvalAddInPlace(ret, ret);
    ret = cc->EvalSub(3.0, ret);
    ret = cc->EvalMult(ret, _tmp);
    return ret;
}