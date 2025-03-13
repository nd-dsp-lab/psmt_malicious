# psmt_malicious
PSMT using CKKS with malicious security.

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
- `n_vaf`: Number of new VAF evaluations $f(x) \mapsto (\frac{3}{2}f(x) - \frac{1}{2})^{2}$.

#### Optional Parameter
- `n_cleanse`: Number of cleanse function $f(x) = -2x^{3} + 3x^{2}$.
- `depth`: Required depth for running the protocol. (TODO: automatically calculate the required depth)

# Presets for Each Domain Size

|  | 6  | 8  | 10     | 12    | 14     | 16      | 18    | 20    |
|-------|----|----|--------|-------|--------|---------|-------|-------|
| $k$   | 17 | 17 | 6.75   | 6.75  | 6.75   | 17      | 17    | 6.75  |
| $L$   | 4  | 4  | 2.59   | 2.59  | 2.59   | 4       | 4     | 2.59  |
| $R$   | 4  | 4  | 158.54 | 91.09 | 148.45 | 5112.73 | 73139 | 12583 |
| n_dep | 2  | 3  | 2      | 4     | 5      | 2       | 1     | 5     |
| n_vaf | 3  | 4  | 8      | 7     | 8      | 16      | 20    | 16    |
| depth | 16 | 19 | 22     | 25    | 28     | 32      | 35    | 38    |
