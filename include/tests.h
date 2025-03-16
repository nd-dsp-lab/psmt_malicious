#ifndef TEST_H
#define TEST_H

int testFullNewVAF();
int testFullPrev();
int testFullPipeline(double sigma, double kappa);
int testFullPipeline64();
int testFullPipelineBinary();

int testVAFs(
    // VAF paramaeters
    double k, double L, double R, uint32_t n_dep, uint32_t n_vaf, uint32_t n_cleanse, uint32_t depth, bool isNewVAF
);

#endif


// std::vector<double> zeroes(65536, 0.0);
//     Plaintext zeroPlain = cryptoContext->MakeCKKSPackedPlaintext(zeroes);
//     Ciphertext<DCRTPoly> ret = cryptoContext->Encrypt(zeroPlain, publicKey); // initialize with zero

//     for (size_t i = 0; i < numCiphertexts; ++i) {
//         auto ret_temp = cryptoContext->EvalSub(queryCipher, encryptedChunks[0]);
//         ret = cryptoContext->EvalAdd(ret, ret_temp);
//     }