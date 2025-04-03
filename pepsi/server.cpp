#include "pepsi_server.h"
#include "pepsi_client.h"
#include "pepsi_core.h"

using namespace lbcrypto;

PEPSIDB constructPEPSIDB (
    CryptoContext<DCRTPoly> cc,
    PublicKey<DCRTPoly> pk,
    std::vector<uint64_t> dataVec,
    uint32_t numCtxt,
    uint32_t kVal,   
    bool isEncrypted
) {
    uint32_t numData = dataVec.size();
    uint32_t ringDim = cc->GetRingDimension();
    uint32_t prime = cc->GetEncodingParams()->GetPlaintextModulus();

    std::vector<std::vector<int64_t>> cwVec(numData);

    std::vector<std::vector<uint64_t>> table = chooseTable(numCtxt);

    #pragma omp parallel for 
    for (uint32_t i = 0; i < numData; i++) {
        cwVec[i] = getCWTable(dataVec[i], numCtxt, kVal, table);
    }

    // Encode Data w.r.t components
    uint32_t numChunks = (numData / ringDim) + (numData % ringDim != 0);
    std::vector<PEPSIChunk> chunks(numChunks);
    std::vector<PEPSIPtxtChunk> ptchunks(numChunks);
    Plaintext _ptxt; Ciphertext<DCRTPoly> _ctxt;

    // Make Chunks 
    for (uint32_t i = 0; i < numChunks; i++) {
        std::vector<Ciphertext<DCRTPoly>> payload(numCtxt);
        std::vector<Plaintext> ptpayload(numCtxt);
        uint32_t offset = i * ringDim;
        for (uint32_t j = 0; j < numCtxt; j++) {
            std::vector<int64_t> _tmp(ringDim, 0);
            for (uint32_t k = 0; k < ringDim; k++) {

                if (offset + k >= numData) {
                    _tmp[i] = -1;
                } else {
                    _tmp[i] = cwVec[offset + k][j];
                }
            }   
            _ptxt = cc->MakePackedPlaintext(_tmp);
            _ctxt = cc->Encrypt(_ptxt, pk);
            payload[j] = _ctxt;
            ptpayload[j] = _ptxt;
        }
        PEPSIChunk chunk {
            payload, numCtxt, kVal
        };
        PEPSIPtxtChunk ptchunk {
            ptpayload, numCtxt, kVal
        };
        chunks[i] = chunk;
        ptchunks[i] = ptchunk;
    }

    // Compute ptDiv
    // This corresponds to (k-1)!
    int64_t divVal = 1;
    for (int64_t i = 1; i < (int64_t)kVal; i++) {
        divVal *= i;
        divVal = divVal % prime;
    }
    std::vector<int64_t> ptVec(ringDim, divVal);
    Plaintext ptDiv = cc->MakePackedPlaintext(ptVec);

    return PEPSIDB {
        chunks, ptchunks, 
        numChunks, ptDiv, numCtxt, kVal, 
        isEncrypted
    };
}


ResponsePEPSIServer compPEPSIInter(
    CryptoContext<DCRTPoly> cc,
    PublicKey<DCRTPoly> pk,
    PEPSIQuery query,
    PEPSIDB DB
) {     
    uint32_t numChunks = DB.numChunks;
    std::vector<Ciphertext<DCRTPoly>> retVec(numChunks);

    if (DB.isEncrypted) {
        #pragma omp parallel for
        for (uint32_t i = 0; i < numChunks; i++) {
            retVec[i] = arithCWEQ(
                cc, query.payload, DB.chunks[i].payload, 
                DB.ptDiv, DB.kVal
            );
        }
    } else {
        #pragma omp parallel for
        for (uint32_t i = 0; i < numChunks; i++) {
            retVec[i] = arithCWEQPtxt(
                cc, query.payload, DB.ptxtChunks[i].payload, 
                DB.ptDiv, DB.kVal
            );
        }
    }

    // Do Additive Aggregation
    Ciphertext<DCRTPoly> ret = cc->EvalAddMany(retVec);

    // Compute Random Mask
    Ciphertext<DCRTPoly> maskVal = genRandCiphertext(cc, pk, 16);

    // Compress ALL
    ret = cc->Compress(ret, 3);
    maskVal = cc->Compress(maskVal, 3);

    // Done!
    return ResponsePEPSIServer { ret, maskVal };
}