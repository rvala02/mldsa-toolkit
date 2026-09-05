# GnuTLS Test Harness for ML-DSA Side-Channel Analysis Toolkit

This directory contains helper programs to perform side-channel timing analysis on GnuTLS's ML-DSA implementation.

Two harnesses are provided:
- **timing.c** measures the complete gnutls_privkey_sign_data2() signing operation.
- **timing_no_encode.c** reads an internal cycle counter exposed by a patched GnuTLS build, allowing the timed region to stop inside the ML-DSA signing implementation before signature encoding.

## Building

1. **Build or install GnuTLS with ML-DSA support.**

- **timing.c** can be built against a regular GnuTLS build with ML-DSA support.
- **timing_no_encode.c** requires the patched GnuTLS/Leancrypto build that exports:

```
gnutls_ml_dsa_last_core_cycles
```
- The patched build also forces deterministic ML-DSA signing by passing NULL as the optional randomness callback to Leancrypto.

2. **Compile the harnesses.**

```
$ cd gnutls

gcc -O2 -Wall -Wextra -std=gnu11 \
    timing.c \
    -o timing \
    $(pkg-config --cflags --libs gnutls)

gcc -O2 -Wall -Wextra -std=gnu11 \
    timing_no_encode.c \
    -o timing_no_encode \
    $(pkg-config --cflags --libs gnutls)
```

3. **Run the harness.**

- Single PEM private key, concatenated fixed-length messages:
```
$ ./timing -i messages.bin -o sigs.bin -t raw_times.bin -k sk.pem -n 32 -s 44
```
- The timing_no_encode variant uses the same input format:
```
$ ./timing_no_encode -i messages.bin -o sigs.bin -t raw_times.bin -k sk.pem -n 32 -s 44
```
- Parameter sets 44, 65, and 87 correspond to ML-DSA-44, ML-DSA-65, and ML-DSA-87.
- Pass -h for full usage.

## Limitations
**timing_no_encode.c** does **not** work with an unmodified GnuTLS library. It requires the timing overlay to be applied to the GnuTLS source and the resulting libgnutls.so to export gnutls_ml_dsa_last_core_cycles.