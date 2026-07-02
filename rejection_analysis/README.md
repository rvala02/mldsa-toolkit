# ML-DSA rejection analysis

Scripts for checking whether ML-DSA rejection sampling behaves differently across signing keys.

The main question is whether different keys have the same rejection behavior, or whether some keys are rejected more often or for different reasons.

The analysis checks:

- total rejection rate,
- message-level rejection rate,
- rejection reasons: `z`, `r0`, `ct0`, `hint`,
- first coefficient that violates a bound for `z`, `r0`, `ct0`.

## Scripts

| Script      | Purpose |
| ----------- | ----------- |
| `rejection.py`      | Runs signing attempts and writes raw rejection data.       |
| `extract_rejections.py`   | Converts raw data into CSV files for individual tests.        |
| `analyze_rejections.py`   | Runs statistical tests on the extracted CSV files.        |

## 1. Collect rejection data

```
python rejection.py \ 
  --keys-dir keys/ \ 
  --messages messages.bin \ 
  --messages-per-key 1000 \ 
  --scheme 65 \ 
  --out raw_rejections.csv
```
This writes:
- `raw_rejections.csv`
- `raw_rejections_coefficients.csv`

`raw_rejections.csv` contains one row per key/message pair.
It records:
- key ID,
- message ID,
- number of signing attempts,
- rejection counts by reason,
- total number of rejections,
- sum of first bad coefficient indexes,
- first rejection reason.

`raw_rejections_coefficients.csv` contains one row per rejected attempt.
It records:
- key ID,
- message ID,
- attempt ID,
- rejection reason,
- first bad coefficient index,
- number of bad coefficients.

Keys must be stored as:

```
key_000/ 
key_001/ 
key_002/ 
...
```
Each key directory must contain: `sk.pem`

The message file is a binary file with concatenated 32-byte messages.

Messages are assigned to keys in block. For example, with `--messages-per-key 1000`:

```
key_000 -> messages 0..999 
key_001 -> messages 1000..1999 
key_002 -> messages 2000..2999
```

## 2. Extract test files
```
python extract_rejections.py \ 
  --input raw_rejections.csv \ 
  --coeff-input raw_rejections_coefficients.csv \ 
  --out-dir extracted/
```

The coefficient input is optional. Without it, coefficient-level tests are skipped.
The extractor creates:

| File      | Purpose |
| ----------- | ----------- |
| `test_overall_rejection_by_key.csv`      | Accepted attempts vs rejected attempts per key.       |
| `test_message_rejection_by_key.csv`   | Messages accepted immediately vs messages with at least one rejection.        |
| `test_z_rejection_by_key.csv`   | `z` rejections vs all non-`z` attempts.    |
| `test_r0_rejection_by_key.csv`   | `r0` rejections vs all non-`r0` attempts.    |
| `test_ct0_rejection_by_key.csv`   | `ct0` rejections vs all non-`ct0` attempts.    |
| `test_hint_rejection_by_key.csv`   | Hint rejections vs all non-hint attempts.    |
| `test_rejection_reason_by_key.csv`   | Distribution of rejection reasons per key.    |
| `test_first_rejecting_coeff_by_key.csv`   | First rejecting coefficient frequencies per key and reason.    |
| `test_sum_first_bad_coeff_by_key.csv`   | Per-message sums of first bad coefficient indexes.    |

## 3. Run all analyses

```
python analyze_rejections.py --all -o extracted/
```
Results are written to: `extracted/analysis_results/`

Important files:

| File      | Purpose |
| ----------- | ----------- |
| `report.txt`      | Short readable summary.       |
| `report.csv`   | Combined machine-readable summary.        |
| `single_table_results.csv`   | Results for ordinary contingency-table tests.    |
| `first_rejecting_coeff_results.csv`   | Coefficient-level test results (experimental).    |
| `first_coeff_bin_results.csv`   | Binned coefficient-distribution results.    |

### Run selected analysis

#### Overall rejection rate

```
python analyze_rejections.py \ 
  --test overall-rejection \ 
  --input extracted/test_overall_rejection_by_key.csv \ 
  --out analysis/overall_rejection_results.csv
```

#### Message-level rejection rate

```
python analyze_rejections.py \ 
  --test message-rejection \ 
  --input extracted/test_message_rejection_by_key.csv \ 
  --out analysis/message_rejection_results.csv
```
#### One rejection reason

```
python analyze_rejections.py \ 
  --test reason-vs-other \ 
  --reason r0 \ 
  --input extracted/test_r0_rejection_by_key.csv \ 
  --out analysis/r0_rejection_results.csv
```

#### Rejection reason distribution
```
python analyze_rejections.py \ 
  --test reason-distribution \ 
  --input extracted/test_rejection_reason_by_key.csv \ 
  --out analysis/reason_distribution_results.csv
```

#### First rejecting coefficient (experimental)
```
python analyze_rejections.py \ 
  --test first-coeff \ 
  --input extracted/test_first_rejecting_coeff_by_key.csv \ 
  --out analysis/first_coeff_results.csv
```

Filter by reason:
```
python analyze_rejections.py \ 
  --test first-coeff \ 
  --reason z \ 
  --input extracted/test_first_rejecting_coeff_by_key.csv \ 
  --out analysis/first_coeff_z_results.csv
```

Filter by reason and coefficient index:
```
python analyze_rejections.py \ 
  --test first-coeff \ 
  --reason z \ 
  --coeff-index 123 \ 
  --input extracted/test_first_rejecting_coeff_by_key.csv \ 
  --out analysis/first_coeff_z_123_results.csv
```

#### Binned first rejecting coefficient distribution
```
python analyze_rejections.py \ 
  --test first-coeff-bins \ 
  --input extracted/test_first_rejecting_coeff_by_key.csv \ 
  --out analysis/first_coeff_bins_results.csv
```

#### Sum of first bad coefficient indexes
```
python analyze_rejections.py \ 
  --test sum-first-bad-coeff \ 
  --input extracted/test_sum_first_bad_coeff_by_key.csv \ 
  --out analysis/sum_first_bad_coeff_results.csv
```

### Tests
| Test | Question | Data | Method |
|---|---|---|---|
| `overall-rejection` | Do keys differ in total rejection rate? | Counts | Chi-square/Fisher |
| `message-rejection` | Do keys differ in how often messages need at least one rejection? | Counts | Chi-square/Fisher |
| `reason-vs-other` | Does one rejection reason occur more often for some keys? | Counts | Chi-square/Fisher |
| `reason-distribution` | Do keys differ in the mix of rejection reasons? | Counts | Chi-square |
| `first-coeff` | Does one coefficient appear as the first bad coefficient more often for some keys? | Counts | Chi-square/Fisher |
| `first-coeff-bins` | Does the binned distribution of first bad coefficients differ between keys? | Counts | Chi-square |
| `sum-first-bad-coeff` | Do per-message sums of first bad coefficient indexes differ between keys? | Numerical blocked values | Friedman |

### Statistical methods

| Method | Use |
|---|---|
| `auto` | Fisher for 2x2 tables, chi-square otherwise. |
| `chi2` | Chi-square independence test across keys. |
| `fisher` | Fisher exact test for 2x2 tables. |
| `binom` | Pairwise binomial diagnostic. |
| `friedman` | Blocked non-parametric test for `sum-first-bad-coeff` (experimental).|

For most categorical tests, the null hypothesis is:

The outcome distribution is independent of the key.

A small p-value means the observed counts are unlikely under that null hypothesis.