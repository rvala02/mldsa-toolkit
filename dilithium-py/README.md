# dilithium-py Test Harness for ML-DSA Side-Channel Analysis Toolkit

This directory contains Python scripts to measure ML-DSA signing using the
**dilithium-py** reference (PEM keys, `ML_DSA` API).

## Building

1. Run the harness

Single PEM key, configurable message size (default 32 bytes); timings are text
with a `raw times` header:

```console
$ python3 timing.py -i messages.bin -s mldsa-44 -k sk.pem --size 32
```

`timing_no_encode.py` is the variant that excludes signature packing from the
timed region (same flags as `timing.py`).

`key_timing.py` uses a new key for each message. `-k` is a binary schedule (many
raw keys in a row), e.g. from `scripts/generate_schedule.py`.

```console
$ python3 key_timing.py -k schedule.bin -d messages.bin -t raw_times.csv -s signatures.bin -m 44
```

## Limitations

`timing.py` / `timing_no_encode.py` use **PEM** private keys. `key_timing.py`
expects **raw** semi-expanded secret keys (2560 / 4032 / 4896 bytes per key for
44 / 65 / 87). Message size for `key_timing.py` is fixed at 32 bytes in the script.
