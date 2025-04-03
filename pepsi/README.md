### OpenFHE implementation of PEPSI (USENIX'24)

This codebase implements PEPSI, which is a two-party PSI protocol through constant-weight encoding. The purpose of this codebase is to compare PEPSI with ours with respect to the membership test.

### How to Run the Program

You can run the protocol by executing the program `main_pepsi` through the following command.

```
./main_pepsi -bitlen <int> -HW <int> -isEncrypted <bool>
```

Here, `-bitlen` and `-HW` denotes the length and the Hamming weight of each codeword, respectively. These two parameters determine the range of IDs that the protocol can handle. The followings are useful pre-sets of `(bitlen, HW)` for various lengths of IDs.

- 128-bit items: (221,32) / (132, 64)
- 80-bit items: (89, 32)
- 64-bit items: (68, 32) / (117, 16)

Since the program measures runtime for the OpenSanction dataset, you need to prepare it in advance. More precisely, you need to place the `hashed_entities_id.csv` file to the directory `data`.