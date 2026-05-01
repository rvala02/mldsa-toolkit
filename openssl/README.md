# OpenSSL Test Harness for ML-DSA Side-Channel Analysis Toolkit

This directory contains helper programs to perform side-channel timing
analysis on OpenSSL's ML-DSA implementation (provider-based EVP API).

## Building

1. Install OpenSSL with ML-DSA support (3.x development headers and libraries;
   your distro package or a local build with ML-DSA enabled).

2. Compile the test harness

```console
$ cd openssl
$ gcc -o timing timing.c -lcrypto
$ gcc -o timing_no_encode timing_no_encode.c -lcrypto
$ gcc -o key_timing key_timing.c -lcrypto
```

If OpenSSL is installed in a custom prefix, add `-I.../include`, `-L.../lib`, and
set `LD_LIBRARY_PATH` when running.

3. Run the test harness

Single PEM private key (`-k`), concatenated messages, binary timing samples on `-t`:

```console
$ ./timing -i messages.bin -o sigs.bin -t raw_times.bin -k sk.pem -n 32 -s 44
```

Raw concatenated secret keys (`-k`) for per-sample signing (`-s` is parameter set):

```console
$ ./key_timing -i messages.bin -o sigs.bin -t raw_times.bin -k schedule.bin -n 32 -s 65
```

Pass `-h` on any binary for full usage.

## Limitations

Timing output on `-t` is **binary** (8 bytes per sample), not the text
`raw times` format. Use `extract.py` with `--binary 8` (and set
`--clock-frequency` appropriately for cycle counters) when classifying.
