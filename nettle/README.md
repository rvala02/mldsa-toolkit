# Nettle Test Harness for ML-DSA Side-Channel Analysis Toolkit

This directory contains helper programs to perform side-channel timing
analysis on Nettle's (yet to be merged) ML-DSA implementation.

## Building

1. Install Nettle

```console
$ git clone --depth=1 --branch=wip/dueno/ml-dsa2 https://git.lysator.liu.se/ueno/nettle.git
$ cd nettle
$ ./.bootstrap
$ ./configure --disable-documentation --prefix=$PWD/install
$ make
$ make install
```

2. Compile the test harness

```console
$ export PKG_CONFIG_PATH=.../nettle/install/lib/pkgconfig
$ gcc -ggdb3 -Wall -o timing timing.c $(pkg-config --cflags --libs nettle hogweed)
$ gcc -ggdb3 -Wall -o key_timing key_timing.c $(pkg-config --cflags --libs nettle hogweed)
```

3. Run the test harness

```console
$ export LD_LIBRARY_PATH=.../nettle/install/lib
$ ./timing -i ../messages.bin -o sig -t timing -k sk.pem -n 100
```

## Limitations

It currently only supports ML-DSA-65 and ML-DSA-87.
