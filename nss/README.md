# NSS Test Harness for ML-DSA Side-Channel Analysis Toolkit

This directory contains helper programs to perform side-channel timing analysis on NSS's ML-DSA implementation through the PKCS#11 signing path.

The directory contains the following harnesses:

- **timing.c** measures ML-DSA signing using a single PEM private key.
- **timing_no_encode.c** uses the internal timing counter exposed by a patched NSS/freebl build to measure signing without final signature encoding.
- **key_timing.c** performs timing measurements using a different private key for each sample.
- **key_timing_no_encode.c** combines per-sample keys with the internal no-encode timing counter.
- **readpem.c / readpem.h** provide the helper code used to import ML-DSA PKCS#8 PEM private keys into NSS.

## Building

1. **Build or install NSS with ML-DSA support.**
- The regular timing harnesses use the NSS PKCS#11 API.
- The *_no_encode harnesses require the patched NSS build that exports:
```
MLDSA_GetLastCoreCycles()
```
2. **Compile the harnesses.**
```
$ cd nss 

$ gcc -O2 -Wall -Wextra -std=gnu11 \ 
    timing.c readpem.c \ 
    -o timing \ 
    $(pkg-config --cflags --libs nss) \ 
    -ldl 

$ gcc -O2 -Wall -Wextra -std=gnu11 \ 
    timing_no_encode.c readpem.c \ 
    -o timing_no_encode \ 
    $(pkg-config --cflags --libs nss) \ 
    -ldl 

$ gcc -O2 -Wall -Wextra -std=gnu11 \ 
    key_timing.c readpem.c \ 
    -o key_timing \ 
    $(pkg-config --cflags --libs nss) \ 
    -ldl 

$ gcc -O2 -Wall -Wextra -std=gnu11 \ 
    key_timing_no_encode.c readpem.c \ 
    -o key_timing_no_encode \ 
    $(pkg-config --cflags --libs nss) \ 
    -ldl
```

## Running
The **timing** and **timing_no_encode** harnesses use a single ML-DSA private key in PKCS#8 PEM format.

```
$ ./timing -i messages.bin -o sigs.bin -t raw_times.bin -k sk.pem -n 32 -s 44 
$ ./timing_no_encode -i messages.bin -o sigs.bin -t raw_times.bin -k sk.pem -n 32 -s 44
```
- The input file contains concatenated messages. -n specifies the size of each individual message in bytes.

The **key_timing** and **key_timing_no_encode** variants use a different raw ML-DSA private key for each message. The key file contains the raw private keys concatenated one after another.

```
$ ./key_timing -i messages.bin -o sigs.bin -t raw_times.bin -k schedule.bin -n 32 -s 44 
$ ./key_timing_no_encode -i messages.bin -o sigs.bin -t raw_times.bin -k schedule.bin -n 32 -s 44
```
Parameter sets 44, 65, and 87 correspond to ML-DSA-44, ML-DSA-65, and ML-DSA-87. ML-DSA-44 is used by default when -s is omitted.

Pass -h on any binary for full usage.
## Key handling
**readpem.c** and **readpem.h** are used to import external ML-DSA private keys into NSS.

For the fixed-key harnesses, the private key is supplied as a PKCS#8 PEM file and imported as an NSS session key before the signing loop.

The key_timing* variants use a different private key for each measurement sample.

## Limitations
The ***_no_encode** harnesses do not work with an unmodified NSS installation. They require the timing overlay to be applied to the NSS source and the resulting freebl library to export **MLDSA_GetLastCoreCycles()**.

Only deterministic ML-DSA signing is used.