
## File Naming Convention

# Database files

Within the code, the relevant CSV file is specified by:

```cpp
std::string dbFilename = "../data/" + std::to_string(sigma) + "_bits/hashed_chunks_"
    + std::to_string(sigma) + "_" + std::to_string(kappa) + ".csv";
```

The database files will be named `hashed_chunks_<sigma>_<kappa>.csv` and placed in folder `../data/<sigma>_bits/`.
For example, if sigma=64 and kappa=8, the file would be:
`../data/64_bits/hashed_chunks_64_8.csv`.

# Query file

Similarly, for the query files, the naming convention follows the same pattern, but they reside in a subfolder named `../data/<sigma>_bits/query/`.

Note: The query file here only contains a single query (consisting of one hashed value split into k(kappa) chunks in each row). The code then replicates this single query across multiple slots of the ciphertext.


# Generating the Files

You can generate the hashed database `hashed_chunks_<sigma>_<kappa>.csv` and query file `hashed_chunks_<sigma>_<kappa>_query.csv` using the provided `do_hash_and_chunk.py` script. This script:

1. Reads IDs from `./data/entity_ids.csv`, which contains watchlist records obtained from the OpenSanctions Regulatory Datasets (https://www.opensanctions.org/datasets/regulatory/).

2. Hashes each entity ID to `sigma` bits.

3. Splits (chunks) that hashed value into `k(kappa)` pieces.

4. Outputs the resulting CSV file in the format described above.
