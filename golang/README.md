# Go Test Harness for ML-DSA Side-Channel Analysis Toolkit

This directory contains helper programs to perform timing analysis on Go's
standard library ML-DSA implementation (`crypto/internal/fips140/mldsa`).

## Building

1. Copy or symlink this directory under the Go source tree (the `mldsa` package
   is internal to `crypto` and cannot be imported from a normal module path):

```console
$ cp -r golang $GOROOT/src/crypto/mldsa_timing
$ cd $GOROOT/src/crypto/mldsa_timing
```

2. Compile the harness (each file is its own `main` package):

```console
$ go build -o timing timing.go
$ go build -o timing_no_encode timing_no_encode.go
$ go build -o key_timing key_timing.go
$ go build -o key_timing_no_encode key_timing_no_encode.go
```

Use a Go toolchain that actually ships `crypto/internal/fips140/mldsa`.

3. Run the harness

Fixed key, 32-byte messages; timings are text (`raw times` header, nanoseconds per line):

```console
$ ./timing -i messages.bin -o raw_times.txt -k seed.bin -m 44
```

One raw private key per sample (32-byte seeds concatenated in `schedule.bin`):

```console
$ ./key_timing -i messages.bin -o sigs.bin -t raw_times.txt -k schedule.bin -n 32 -m 44
```

## Limitations

Keys must be **32-byte binary seeds** (what `NewPrivateKey*` accepts). There is
no PEM support in these tools. The `*_no_encode` programs expect a modified
`SignDeterministic` with an extra return value.
