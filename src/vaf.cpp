#include "vaf.h"

using namespace lbcrypto;

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
// x^2(3 - 2x)
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