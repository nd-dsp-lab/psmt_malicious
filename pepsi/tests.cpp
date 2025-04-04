#include "pepsi_test.h"
#include "fhe_init_pepsi.h"
#include "chunk_reader.h"

// Helper for Simulation
std::vector<uint64_t> genDataPEPSI(
    int32_t numItem
) {
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<uint64_t> dist(3, ((uint64_t)1 << 16) - 1);

    std::vector<uint64_t> ret;
    for (int32_t i = 0; i < numItem; i++) {
        ret.push_back(dist(gen));
    }
    return ret;
}

size_t ctxtSize(Ciphertext<DCRTPoly>& ctxt) {
    size_t size = 0;
    for (auto& element : ctxt->GetElements()) {
      for (auto& subelements : element.GetAllElements()) {
        auto lenght = subelements.GetLength();
        size += lenght * sizeof(subelements[0]);
      }
    }
    return size;
  };

double calcEltSize(
  uint32_t bitlen,
  uint32_t HW
) {
  double ret = 0;
  for (double i = 1; i <= HW; i++) {
    ret += std::log2(bitlen - i + 1) - std::log2(i);
  }
  return ret;
}


void testPEPSIProtocol(
  uint32_t bitlen,
  uint32_t HW,
  bool isEncrypted
) {
  std::cout << "TEST START!" << std::endl;
  // Calucate Supporting Element Size
  double logEltSize = calcEltSize(bitlen, HW);
  std::cout << "Supporting Element Size (log2): " << logEltSize << std::endl;

  std::cout << "STEP 1-1: Setup FHE" << std::endl;
  uint32_t depth = (int)(std::log2(HW))+isEncrypted;
  std::cout << "PEPSI depth: " << depth << std::endl;
  //print it
  FHEParamsBFV params;
  params.multiplicativeDepth = depth;
  params.ringDim = 1<<14;
  params.ptModulus = 65537;

  FHEContext fheContext = InitFHEBFV(params);
  auto cc = fheContext.cryptoContext;
  auto pk = fheContext.keyPair.publicKey;
  auto sk = fheContext.keyPair.secretKey;

  std::cout << "Step 1-2: Setup Databases" << std::endl;
  // TODO: Read Data from the server
  std::vector<double> chunks = ChunkReader::readChunks("../data/hashed_entity_ids.csv");

  std::cout << "Size of Database: " << chunks.size() << std::endl;

  std::vector<uint64_t> msgVec(chunks.size());
  for (uint32_t i = 0; i < chunks.size(); i++) {
    msgVec[i] = round(chunks[i]);
  }

  std::cout << "Step 1-3: Server Side Preprocessing" << std::endl;
  // Note that current implemention is a bogus code (just for performance evaluation)
  // It is okay to remain that way

  
  PEPSIDB serverDB = constructPEPSIDB(
    cc, pk, msgVec, bitlen, HW, isEncrypted
  );
  
  int numCtxtsTotal = serverDB.chunks.size() * bitlen;
  std::cout << "\n Number of server ctxts: " << numCtxtsTotal << std::endl;
  std::cout << "Step 2: Client Side Computation" << std::endl;
  std::cout << "Step 3: Query Encryption" << std::endl;
  PEPSIQuery query = encryptClientData(cc, pk, 42, bitlen, HW);
  double serverSingleSize = ctxtSize(query.payload[0]);

  std::cout << "Size of single DB ciphertext: " << (serverSingleSize) / 1000000 << " MB" << std::endl;

  size_t querySize = ctxtSize(query.payload[0]) * query.numCtxt;

  std::cout << "Step 4: Do Intersection" << std::endl;
  ResponsePEPSIServer interResCtxt;

  auto t1 = std::chrono::high_resolution_clock::now();
  interResCtxt = compPEPSIInter(cc, pk, query, serverDB);
  auto t2 = std::chrono::high_resolution_clock::now();
  double timeSec = std::chrono::duration<double>(t2 - t1).count();
  std::cout << "Intersection Done! Time Elapsed: " << timeSec << "s" << std::endl;
  std::cout << "Step 5: Receive Result" << std::endl;
  auto ret = checkIntResult(cc, sk, interResCtxt.isInter);
  std::cout << "Inter Result: " << ret << std::endl;
  std::cout << "OpenFHE Query Size: " << (double)(querySize) / 1000000 << "MB" << std::endl;
}
