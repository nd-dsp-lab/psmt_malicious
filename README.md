# psmt_malicious
Labeled Functional PMT using CKKS with malicious security.

# Build the Project

You can build the project by the following command line.

```
make clean
rm -r build
mkdir build && cd build
cmake -S .. -B .
make 
```

The following two executable programs will be build.

- `main`: Test for the full pipeline.
- `main_vaf`: Test for the VAF only.

# VAF Parameters

The proposed VAF takes several parameters for each domain size.

#### WeakDEP Parameters ($f(x) = \frac{3\sqrt{3}}{2k\sqrt{k}}x(k - x^{2})$)
- `k`: weakDEP Parameter
- `L`: Domain extension rate ($\sqrt{k/3} < L < \sqrt{k}$)
- `R`: Base domain size
- `n_dep`: Number of DEP extensions

#### VAF Parameters
- `isNewVAF`: Naive Squaring vs. New Transformation
- `n_vaf`: Number of transformations ($f(x) \mapsto $f(x)^{2}$ or $f(x) \mapsto (\frac{3}{2}f(x) - \frac{1}{2})^{2}$).


#### Optional Parameter
- `n_cleanse`: Number of cleanse function $f(x) = -2x^{3} + 3x^{2}$.
- `depth`: Required depth for running the protocol. (TODO: automatically calculate the required depth)

# Presets for Each Domain Size

|       | $2^{1}$ | $2^{2}$ | $2^{4}$ | $2^{5}$ | $2^{6}$  | $2^{8}$  | $2^{10}$ | $2^{12}$  | $2^{14}$ | $2^{16}$ | $2^{18}$ | $2^{20}$ |
|-------|----|----|----|----|----|----|--------|-------|--------|---------|-------|-------|
| $k$   | NA | NA | NA | 17 | 17 | 17 | 6.75   | 6.75  | 6.75   | 17      | 17    | 6.75  |
| $L$   | NA | NA | NA | 4  | 4  | 4  | 2.59   | 2.59  | 2.59   | 4       | 4     | 2.59  |
| $R$   | 2  | 4  | 16 | 4  | 11 | 4  | 158.54 | 91.09 | 148.45 | 5112.73 | 73139 | 12583 |
| n_dep | 0  | 0  | 0  | 2  | 1  | 3  | 2      | 4     | 5      | 2       | 1     | 5     |
| n_vaf | 4  | 7  | 4  | 3  | 4  | 4  | 8      | 7     | 8      | 16      | 20    | 16    |
| newVAF| F  | F  | T  | T  | T  | T  | T      | T     | T      | T       | T     | T     |
| depth | 7  | 10 | 13 | 16 | 15 | 19 | 22     | 25    | 28     | 32      | 35    | 38    |
