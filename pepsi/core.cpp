#include "pepsi_core.h"


uint64_t choose(uint64_t n, uint64_t k) {
    if (k > n) {
        return 0;
    }
    uint64_t r = 1;
    for (uint64_t d = 1; d <= k; ++d) {
        r *= n--;
        r /= d;
    }
    return r;
}

std::vector<std::vector<uint64_t>> chooseTable(uint64_t n) {
    std::vector<std::vector<uint64_t>> ret(n+1);

    for (uint64_t i = 0; i <= n; i++) {
        ret[i].resize(n+1, 0);  // Correctly size each row
        ret[i][0] = 1;  // First element is always 1

        for (uint64_t j = 1; j <= i; j++) {  // Fix: Change i++ to j++
            ret[i][j] = ret[i-1][j-1] + (j < i ? ret[i-1][j] : 0);
        }
    }
    return ret;
}

// Codeword Mapping
// Perfect Encoding
std::vector<int64_t> getCW(
    uint64_t data,
    uint32_t numCtxt,
    uint32_t kVal
) {
    std::vector<int64_t> ret(numCtxt, 0);
    
    // uint64_t maxSize = choose(numCtxt, kVal);
    // if (maxSize < data) {
    //     throw std::runtime_error("Parameter is TOO small to encode the given value!");
    // }

    uint64_t rem = data;

    for (int32_t i = (int32_t)numCtxt - 1; i >= 0; i--) {
        if (rem > choose(i, kVal)) {
            ret[i] = 1;
            rem -= choose(i, kVal);
            kVal -= 1;
        }
    }
    return ret;
}

std::vector<int64_t> getCWTable(
    uint64_t data,
    uint32_t numCtxt,
    uint32_t kVal,
    std::vector<std::vector<uint64_t>> table
) {
    std::vector<int64_t> ret(numCtxt, 0);
    
    // uint64_t maxSize = choose(numCtxt, kVal);
    // if (maxSize < data) {
    //     throw std::runtime_error("Parameter is TOO small to encode the given value! maxSize vs data:"
    //         + std::to_string(data) + " vs " + std::to_string(maxSize)
    //     );
    // }

    uint64_t rem = data;

    for (int32_t i = (int32_t)numCtxt - 1; i >= 0; i--) {
        if (rem > table[i][kVal]) {
            ret[i] = 1;
            rem -= table[i][kVal];
            kVal -= 1;
        }
    }
    return ret;
}


// Arith-CW-EQ
Ciphertext<DCRTPoly> arithCWEQ(
    CryptoContext<DCRTPoly> cc,
    std::vector<Ciphertext<DCRTPoly>> ctxt1,
    // std::vector<Plaintext> ctxt2,
    std::vector<Ciphertext<DCRTPoly>> ctxt2,
    Plaintext ptDiv,
    uint32_t kVal
) {
    uint32_t numCtxt = ctxt1.size();

    // Inner Product
    std::vector<Ciphertext<DCRTPoly>> retVec(numCtxt); 

    // Step 1. Multiply Each Other
    for (uint32_t i = 0; i < numCtxt; i++) {
        retVec[i] = cc->EvalMult(ctxt1[i], ctxt2[i]);
    }

    // Step 2. Add Many Ciphertexts
    Ciphertext<DCRTPoly> ret = cc->EvalAddMany(retVec);


    // Evaluate Equality Circuit
    // 1/k! * prod(x-i)
    retVec.resize(kVal); 

    // Step 1. Prepare the inner term
    for (uint32_t i = 0; i < kVal; i++) {
        std::vector<int64_t> ptNum(cc->GetRingDimension(), i);
        Plaintext _tmp = cc->MakePackedPlaintext(ptNum);
        retVec[i] = cc->EvalSub(_tmp, ret);
    }

    // Step 2. Multiply ALL!
    ret = cc->EvalMultMany(retVec);

    // Step 3. Multiply Inverse
    ret = cc->EvalMult(ret, ptDiv);

    // Done!
    return ret;
}

Ciphertext<DCRTPoly> arithCWEQPtxt(
    CryptoContext<DCRTPoly> cc,
    std::vector<Ciphertext<DCRTPoly>> ctxt,
    // std::vector<Plaintext> ctxt2,
    std::vector<Plaintext> ptxt,
    Plaintext ptDiv,
    uint32_t kVal
) {
    uint32_t numCtxt = ctxt.size();

    // Inner Product
    std::vector<Ciphertext<DCRTPoly>> retVec(numCtxt); 

    // Step 1. Multiply Each Other
    for (uint32_t i = 0; i < numCtxt; i++) {
        retVec[i] = cc->EvalMult(ctxt[i], ptxt[i]);
    }

    // Step 2. Add Many Ciphertexts
    Ciphertext<DCRTPoly> ret = cc->EvalAddMany(retVec);


    // Evaluate Equality Circuit
    // 1/k! * prod(x-i)
    retVec.resize(kVal); 

    // Step 1. Prepare the inner term
    for (uint32_t i = 0; i < kVal; i++) {
        std::vector<int64_t> ptNum(cc->GetRingDimension(), i);
        Plaintext _tmp = cc->MakePackedPlaintext(ptNum);
        retVec[i] = cc->EvalSub(_tmp, ret);
    }

    // Step 2. Multiply ALL!
    ret = cc->EvalMultMany(retVec);

    // Step 3. Multiply Inverse
    ret = cc->EvalMult(ret, ptDiv);

    // Done!
    return ret;
}

// Utility Function for Creating a Random Masking Vector
Ciphertext<DCRTPoly> genRandCiphertext(
    CryptoContext<DCRTPoly> cc,
    PublicKey<DCRTPoly> pk,
    uint32_t numRand
) {
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<int64_t> dist(0, cc->GetEncodingParams()->GetPlaintextModulus() - 1);
    
    std::vector<int64_t> randVec(numRand);

    for (uint32_t i = 0; i < numRand; i++) {
        randVec[i] = dist(gen);
    }

    std::vector<int64_t> msgVec(cc->GetRingDimension(), 0);

    #pragma omp parallel for
    for (uint32_t i = 0; i < cc->GetRingDimension(); i++) {
        msgVec[i] = randVec[i % numRand];        
    }

    Plaintext ptxt = cc->MakePackedPlaintext(msgVec);
    return cc->Encrypt(ptxt, pk);
}

// Utility Function for Summing Across All the Slots
Ciphertext<DCRTPoly> sumOverSlots(
    CryptoContext<DCRTPoly> cc,
    Ciphertext<DCRTPoly> ctxt
) {
    Ciphertext<DCRTPoly> _tmp;
    Ciphertext<DCRTPoly> ret = ctxt->Clone();
    for (uint32_t i = 1; i < cc->GetRingDimension(); i*=2) {
        _tmp = cc->EvalRotate(ret, i);
        ret = cc->EvalAdd(ret, _tmp);
    }
    return ret;
}