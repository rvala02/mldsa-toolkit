# ML-DSA Side-Channel Analysis Toolkit

A toolkit for performing side-channel timing analysis on ML-DSA signature
implementations. It extracts intermediate values from ML-DSA signatures and
correlates them with timing measurements to identify potential leakage.

## Layout

| Path | Role |
|------|------|
| `extract.py` | Feature extraction and alignment with timings |
| `scripts/` | Helpers (`generate_data.py`, `generate_schedule.py`, …) |
| `dilithium-py/` | Python timing harness (PEM keys) — see `dilithium-py/README.md` |
| `openssl/`, `nettle/` | C harnesses — see each directory’s `README.md` |
| `golang/` | Go ML-DSA harness — see `golang/README.md` |

Timing collection differs per backend (binary vs text timings, PEM vs raw keys,
single key vs schedule); read the README for the stack you use.

## Prerequisites

- **tlsfuzzer**: `extract.py` and `analysis.py` expect tlsfuzzer on `PYTHONPATH`
  (as in the example below). Layout may vary; adjust paths to match your clone.

## Example Usage

Complete example for ML-DSA-44:

```bash
# 1. Generate test data
python scripts/generate_data.py

# 2. Collect timing data (defaults write under mldsa-44/results/ if paths omitted)
python dilithium-py/timing.py -s mldsa-44 -i data.bin -k mldsa-44/keys/sk.pem

# 3. Extract features
PYTHONPATH=./tlsfuzzer python extract.py \
  --ml-dsa-keys mldsa-44/keys/sk.pem \
  --ml-dsa-sigs mldsa-44/results/signatures.bin \
  --ml-dsa-msgs data.bin \
  --raw-times mldsa-44/results/timings.csv \
  --clock-frequency 1000 \
  -o output-mldsa-44 \
  --verbose

# 4. Analyze a specific feature (example: bit-size-y)
cp output-mldsa-44/measurements-bit-size-y.csv output-mldsa-44/bit-size-y/measurements.csv

PYTHONPATH=./tlsfuzzer python tlsfuzzer/tlsfuzzer/analysis.py \
    -o output-mldsa-44/bit-size-y/ \
    --verbose \
    --summary-only \
    --Hamming-weight \
    --minimal-analysis \
    --no-sign-test
```
