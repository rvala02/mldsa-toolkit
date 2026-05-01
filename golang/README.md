Go test harness for ML-DSA signing (stdlib `crypto/internal/fips140/mldsa`).

Put these sources under `$GOROOT/src/crypto/` (any folder name, e.g. `mldsa_timing`) so they may import the internal package. Build each program separately:

```
cd $GOROOT/src/crypto/mldsa_timing
go build -o timing timing.go
go build -o key_timing key_timing.go
```

(`timing_no_encode.go` / `key_timing_no_encode.go` build the same way if your tree has the matching `SignDeterministic` API.)

Prepare inputs as in the repo root README. Keys are **32-byte binary seeds** (not PEM).

Run **one fixed key**, 32-byte messages:

```
./timing -i messages.bin -o raw_times.txt -k seed.bin -m 44
```

Optional signatures: add `-s sigs.bin`.

Run **one seed per sample** (messages of length `-n`):

```
./key_timing -i messages.bin -o sigs.bin -t raw_times.txt -k schedule.bin -n 32 -m 44
```

Extract / continue analysis as in the main readme (`extract.py`, etc.).
