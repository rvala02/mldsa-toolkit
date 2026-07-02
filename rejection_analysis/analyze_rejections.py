"""Analysis of ML-DSA rejection-sampling measurements.

Per-test usage:
    python analyze_rejections.py \\
        --test message-rejection \\
        --input extracted/test_message_rejection_by_key.csv \\
        --out analysis/message_results.csv

Batch usage:
    python analyze_rejections.py --all -o extracted/
"""

import argparse
import csv
import sys
from itertools import combinations
from pathlib import Path

import numpy as np
from scipy import stats

REASONS = ("z", "r0", "ct0", "hint")
FIRST_COEFF_REASONS = ("z", "r0", "ct0")

INPUT_FILES = {
    "overall_rejection": "test_overall_rejection_by_key.csv",
    "message_rejection": "test_message_rejection_by_key.csv",
    "reason_distribution": "test_rejection_reason_by_key.csv",
    "sum_first_bad_coeff": "test_sum_first_bad_coeff_by_key.csv",
    "first_coeff": "test_first_rejecting_coeff_by_key.csv",
}

SINGLE_TABLE_HEADER = [
    "test",
    "input_file",
    "method",
    "n_keys",
    "key_id_a",
    "key_id_b",
    "table_shape",
    "total_observations",
    "total_signatures",
    "statistic",
    "p_value",
    "dof",
    "p_value_bonferroni",
    "p_value_bh_fdr",
    "notes",
]

BLOCKED_TEST_HEADER = [
    "test",
    "input_file",
    "method",
    "n_keys",
    "n_blocks",
    "table_shape",
    "total_observations",
    "statistic",
    "p_value",
    "dof",
    "notes",
]

FIRST_COEFF_HEADER = [
    "test",
    "reason",
    "coeff_index",
    "method",
    "n_keys",
    "key_id_a",
    "key_id_b",
    "table_shape",
    "total_observations",
    "total_signatures",
    "statistic",
    "p_value",
    "dof",
    "total_count",
    "total_denominator",
    "p_value_bonferroni",
    "p_value_bh_fdr",
    "notes",
]

REPORT_HEADER = [
    "test",
    "reason",
    "coeff_index",
    "method",
    "n_keys",
    "key_id_a",
    "key_id_b",
    "n_blocks",
    "table_shape",
    "total_observations",
    "total_signatures",
    "statistic",
    "p_value",
    "dof",
    "p_value_bonferroni",
    "p_value_bh_fdr",
    "notes",
]


def parse_args():
    parser = argparse.ArgumentParser(
        description="Analyse extracted ML-DSA rejection-sampling measurements",
    )
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument(
        "--all",
        action="store_true",
        help="Run all tests on extracted CSVs in --output directory",
    )
    mode.add_argument(
        "--test",
        choices=[
            "overall-rejection",
            "message-rejection",
            "reason-vs-other",
            "reason-distribution",
            "first-coeff",
            "sum-first-bad-coeff",
            "first-coeff-bins"
        ],
        help="Statistical test to run",
    )
    parser.add_argument(
        "-o", "--output",
        help="Directory containing extracted rejection CSV files (batch mode)",
    )
    parser.add_argument(
        "--input", "-i",
        help="Input CSV for a single test",
    )
    parser.add_argument(
        "--out",
        help="Output CSV for a single test",
    )
    parser.add_argument(
        "--reason",
        choices=list(REASONS),
        help="Rejection reason (required for reason-vs-other; optional filter for first-coeff)",
    )
    parser.add_argument(
        "--coeff-index",
        type=int,
        help="Restrict first-coeff test to one coefficient index",
    )
    parser.add_argument(
        "--method",
        choices=["auto", "chi2", "fisher", "binom"],
        default="auto",
        help="Statistical method for contingency tables (default: auto)",
    )
    parser.add_argument(
        "--alpha",
        type=float,
        default=0.01,
        help="Significance threshold used in report.txt (default: 1e-5)",
    )
    parser.add_argument(
        "--summary-only",
        action="store_true",
        help="Batch mode: print only the final summary",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Print extra progress information",
    )
    parser.add_argument(
        "--bin-size",
        type=int,
        default=256,
        help="Coefficient bin size for first-coeff-bins test (default: 256)",
    )
    return parser.parse_args()


def error(msg):
    print(f"ERROR: {msg}", file=sys.stderr)
    sys.exit(1)


def parse_int(value, field, row_num, non_negative=True):
    try:
        parsed = int(value)
    except ValueError:
        error(f"row {row_num}: {field} must be an integer, got {value!r}")
    if non_negative and parsed < 0:
        error(f"row {row_num}: {field} must be non-negative, got {parsed}")
    return parsed


def require_columns(fieldnames, required, path):
    if fieldnames is None:
        error(f"input file is empty: {path}")
    missing = [col for col in required if col not in fieldnames]
    if missing:
        error(f"{path} missing required columns: {', '.join(missing)}")


def load_aggregated_csv(path, required):
    if not path.exists():
        error(f"input file does not exist: {path}")

    rows = []
    with open(path, newline="") as in_fd:
        reader = csv.DictReader(in_fd)
        require_columns(reader.fieldnames, required, path)
        for row_num, row in enumerate(reader, start=2):
            parsed = {}
            for col in required:
                if col == "reason":
                    parsed[col] = row[col]
                elif col in ("coeff_index", "key_id"):
                    parsed[col] = parse_int(row[col], col, row_num, non_negative=col != "coeff_index")
                else:
                    parsed[col] = parse_int(row[col], col, row_num)
            rows.append(parsed)

    if not rows:
        error(f"input file contains no data rows: {path}")
    return rows


def load_blocked_measurements(path):
    if not path.exists():
        error(f"input file does not exist: {path}")

    required = ["block_id", "key_id", "value"]
    rows = []
    with open(path, newline="") as in_fd:
        reader = csv.DictReader(in_fd)
        require_columns(reader.fieldnames, required, path)
        for row_num, row in enumerate(reader, start=2):
            rows.append({
                "block_id": parse_int(row["block_id"], "block_id", row_num),
                "key_id": parse_int(row["key_id"], "key_id", row_num),
                "value": parse_int(row["value"], "value", row_num),
            })

    if not rows:
        error(f"input file contains no data rows: {path}")
    return rows


def sum_total_signatures(rows):
    return sum(row.get("total_signatures", 0) for row in rows)


def filter_table_rows(rows, value_columns):
    return [row for row in rows if not all(row[col] == 0 for col in value_columns)]


def build_contingency_table(rows, value_columns):
    return np.array([[row[col] for col in value_columns] for row in rows], dtype=int)


def table_shape(table):
    return f"{table.shape[0]}x{table.shape[1]}"


def drop_zero_columns(table):
    if table.size == 0:
        return table
    keep = [i for i in range(table.shape[1]) if table[:, i].sum() > 0]
    if not keep:
        return table[:, :0]
    return table[:, keep]


def select_method(table, method):
    is_2x2 = table.shape == (2, 2)

    if method == "fisher":
        if not is_2x2:
            error("Fisher exact test is valid only for 2x2 tables")
        return "fisher"
    if method == "chi2":
        return "chi2"
    if method == "binom":
        if table.shape[1] != 2:
            error("binomtest requires exactly two columns (event vs complement)")
        return "binom"
    return "fisher" if is_2x2 else "chi2"


def run_binom_pair(key_id_a, key_id_b, row_a, row_b):
    """
    Run a pairwise binomial test comparing one binary outcome between two keys.

    The input rows are expected to contain two counts:
        [event_count, non_event_count]
    """
    k, n = int(row_a[0]), int(row_a.sum())
    denom_b = int(row_b.sum())
    if n == 0 or denom_b == 0:
        return None
    p = row_b[0] / denom_b
    observed_rate = k / n
    result = stats.binomtest(k, n, p, alternative="two-sided")
    return {
        "method": "binom",
        "key_id_a": key_id_a,
        "key_id_b": key_id_b,
        "table_shape": "2x2",
        "total_observations": n + denom_b,
        "statistic": float(observed_rate - p),
        "p_value": float(result.pvalue),
        "dof": "",
        "notes": "binomtest_key_a_vs_key_b",
    }


def run_binom_tests(table, key_ids, method):
    n_keys = table.shape[0]
    if n_keys < 2:
        return [empty_contingency_result(table, key_ids, "skipped: fewer than two keys")]

    if method != "binom":
        return None

    if table.shape[1] != 2:
        error("binomtest requires exactly two columns (event vs complement)")

    table = drop_zero_columns(table)
    if table.shape[1] < 2:
        return [empty_contingency_result(table, key_ids, "skipped: fewer than two non-zero columns")]

    results = []
    pairwise = n_keys >= 3
    for i, j in combinations(range(n_keys), 2):
        outcome = run_binom_pair(key_ids[i], key_ids[j], table[i], table[j])
        if outcome is None:
            continue
        outcome["n_keys"] = n_keys
        outcome["notes"] = "binomtest_pairwise" if pairwise else "binomtest_key_a_vs_key_b"
        results.append(outcome)

    if not results:
        return [empty_contingency_result(table, key_ids, "skipped: no valid key pairs for binomtest")]

    return results


def empty_contingency_result(table, key_ids, note):
    return {
        "method": "",
        "n_keys": len(key_ids) if key_ids else (table.shape[0] if table.size else 0),
        "key_id_a": "",
        "key_id_b": "",
        "table_shape": table_shape(table) if table.size else "0x0",
        "total_observations": int(table.sum()) if table.size else 0,
        "statistic": "",
        "p_value": "",
        "dof": "",
        "p_value_bonferroni": "",
        "p_value_bh_fdr": "",
        "notes": note,
    }


def run_contingency_test(table, key_ids, method):
    """
    Run a statistical test on a key-by-outcome contingency table.

    The input table contains one row per key and one column per observed
    outcome category. Depending on the selected method and shape, this 
    function runs one of the supported contingency-table tests:

    - pairwise binomial tests, when method is binom,
    - Fisher's exact test, for 2x2 tables,
    - chi-square test of independence, for larger tables.
    """
    notes = []
    n_keys, n_cols = table.shape

    if n_keys < 2:
        return [empty_contingency_result(table, key_ids, "skipped: fewer than two keys")]
    if n_cols < 2:
        return [empty_contingency_result(table, key_ids, "skipped: fewer than two columns")]

    binom_results = run_binom_tests(table, key_ids, method)
    if binom_results is not None:
        return binom_results

    table = drop_zero_columns(table)
    n_keys, n_cols = table.shape
    if n_cols < 2:
        return [empty_contingency_result(table, key_ids, "skipped: fewer than two non-zero columns")]

    selected = select_method(table, method)
    if selected == "fisher":
        odds_ratio, p_value = stats.fisher_exact(table)
        return [{
            "method": "fisher",
            "n_keys": n_keys,
            "key_id_a": "",
            "key_id_b": "",
            "table_shape": table_shape(table),
            "total_observations": int(table.sum()),
            "statistic": float(odds_ratio),
            "p_value": float(p_value),
            "dof": "",
            "p_value_bonferroni": "",
            "p_value_bh_fdr": "",
            "notes": "",
        }]

    try:
        chi2, p_value, dof, expected = stats.chi2_contingency(table)
    except ValueError as exc:
        return [empty_contingency_result(table, key_ids, f"skipped: degenerate contingency table ({exc})")]

    if np.any(expected < 5):
        notes.append("low_expected_counts")

    return [{
        "method": "chi2",
        "n_keys": n_keys,
        "key_id_a": "",
        "key_id_b": "",
        "table_shape": table_shape(table),
        "total_observations": int(table.sum()),
        "statistic": float(chi2),
        "p_value": float(p_value),
        "dof": int(dof),
        "p_value_bonferroni": "",
        "p_value_bh_fdr": "",
        "notes": ";".join(notes),
    }]


def pivot_measurements_by_block(rows):
    """
    Group rows by block_id

    rows -> blocks
    columns -> keys
    values -> measured values for a given block/key pair
    """
    blocks = {}
    for row in rows:
        blocks.setdefault(row["block_id"], {})[row["key_id"]] = row["value"]

    key_ids = sorted({row["key_id"] for row in rows})
    complete_block_ids = {
        block_id
        for block_id, values in blocks.items()
        if all(key_id in values for key_id in key_ids)
    }

    notes = []
    incomplete = len(blocks) - len(complete_block_ids)
    if incomplete > 0:
        notes.append(f"dropped {incomplete} incomplete block(s)")

    if not complete_block_ids:
        return None, key_ids, 0, notes

    data = np.array([
        [blocks[block_id][key_id] for key_id in key_ids]
        for block_id in sorted(complete_block_ids)
    ], dtype=float)

    return data, key_ids, len(complete_block_ids), notes


def empty_blocked_result(test_name, input_file, n_keys, n_blocks, note):
    return {
        "test": test_name,
        "input_file": input_file,
        "method": "",
        "n_keys": n_keys,
        "n_blocks": n_blocks,
        "table_shape": f"{n_blocks}x{n_keys}" if n_blocks else "0x0",
        "total_observations": 0,
        "statistic": "",
        "p_value": "",
        "dof": "",
        "notes": note,
    }


def run_friedman_blocked_test(input_file, rows, test_name):
    # Blocks are local message_id per key (not shared global messages).
    data, key_ids, n_blocks, notes = pivot_measurements_by_block(rows)
    n_keys = len(key_ids)

    if n_keys < 3:
        return empty_blocked_result(
            test_name, input_file, n_keys, n_blocks,
            "skipped: Friedman test requires at least three keys",
        )

    if data is None or n_blocks < 1:
        return empty_blocked_result(
            test_name, input_file, n_keys, 0,
            "skipped: no complete blocks with all keys present",
        )

    if n_blocks < 10:
        notes.append("fewer than ten complete blocks; Friedman approximation may be unreliable")

    if np.all(data == data[0, 0]):
        return {
            "test": test_name,
            "input_file": input_file,
            "method": "friedman",
            "n_keys": n_keys,
            "n_blocks": n_blocks,
            "table_shape": f"{n_blocks}x{n_keys}",
            "total_observations": int(data.size),
            "statistic": 0.0,
            "p_value": 1.0,
            "dof": n_keys - 1,
            "notes": "; ".join(notes + ["all blocked values are identical"]),
        }

    try:
        statistic, p_value = stats.friedmanchisquare(
            *(data[:, i] for i in range(n_keys))
        )
    except ValueError as exc:
        return empty_blocked_result(
            test_name, input_file, n_keys, n_blocks, f"skipped: {exc}",
        )

    return {
        "test": test_name,
        "input_file": input_file,
        "method": "friedman",
        "n_keys": n_keys,
        "n_blocks": n_blocks,
        "table_shape": f"{n_blocks}x{n_keys}",
        "total_observations": int(data.size),
        "statistic": float(statistic),
        "p_value": float(p_value),
        "dof": n_keys - 1,
        "notes": "; ".join(notes),
    }


def run_single_table_test(test_name, input_file, rows, value_columns, key_column, method):
    filtered = filter_table_rows(rows, value_columns)
    key_ids = [row[key_column] for row in filtered]
    table = build_contingency_table(filtered, value_columns)
    total_signatures = sum_total_signatures(filtered)
    outcomes = run_contingency_test(table, key_ids, method)
    return [
        {
            "test": test_name,
            "input_file": input_file,
            "total_signatures": total_signatures,
            **outcome,
        }
        for outcome in outcomes
    ]


def empty_first_coeff_result(note):
    return {
        "test": "first_rejecting_coeff_by_key",
        "reason": "",
        "coeff_index": "",
        "method": "",
        "n_keys": 0,
        "key_id_a": "",
        "key_id_b": "",
        "table_shape": "0x0",
        "total_observations": 0,
        "total_signatures": 0,
        "statistic": "",
        "p_value": "",
        "dof": "",
        "total_count": 0,
        "total_denominator": 0,
        "p_value_bonferroni": "",
        "p_value_bh_fdr": "",
        "notes": note,
    }


def run_first_coeff_test(input_file, rows, method, reason_filter=None, coeff_filter=None):
    """
    Test whether first rejecting coefficient frequencies differ by key.

    This function analyzes aggregated first-rejecting-coefficient counts.
    For each rejection reason and coefficient index, it builds a binary
    contingency table comparing:
        
        count = number of times this coefficient was the first bad coefficient
        other = number of rejections for the same reason caused by other coefficients

    (exploratory testing only)
    """
    by_key_reason = {}
    counts = {}
    total_signatures_by_key = {}

    for row in rows:
        if row["reason"] not in FIRST_COEFF_REASONS:
            continue
        if reason_filter is not None and row["reason"] != reason_filter:
            continue
        if coeff_filter is not None and row["coeff_index"] != coeff_filter:
            continue

        key_id = row["key_id"]
        reason = row["reason"]
        coeff_index = row["coeff_index"]
        by_key_reason[(key_id, reason)] = row["total_rejections_for_reason"]
        total_signatures_by_key[key_id] = row["total_signatures"]
        counts[(key_id, reason, coeff_index)] = row["count"]

    pairs = sorted({(reason, coeff_index) for _, reason, coeff_index in counts})
    if not pairs:
        return [empty_first_coeff_result("skipped: no coefficient tests to run")]

    results = []
    for reason, coeff_index in pairs:
        table_rows = []
        key_ids = []
        total_count = 0
        total_denominator = 0

        for (key_id, row_reason), denominator in sorted(by_key_reason.items()):
            if row_reason != reason:
                continue
            count = counts.get((key_id, reason, coeff_index), 0)
            other = denominator - count
            if count == 0 and other == 0:
                continue
            table_rows.append({"key_id": key_id, "count": count, "other": other})
            key_ids.append(key_id)
            total_count += count
            total_denominator += denominator

        table = build_contingency_table(table_rows, ["count", "other"])
        total_signatures = sum(
            total_signatures_by_key[row["key_id"]] for row in table_rows
        )
        outcomes = run_contingency_test(table, key_ids, method)
        for outcome in outcomes:
            results.append({
                "test": "first_rejecting_coeff_by_key",
                "reason": reason,
                "coeff_index": coeff_index,
                "total_count": total_count,
                "total_denominator": total_denominator,
                "total_signatures": total_signatures,
                "input_file": input_file,
                "p_value_bonferroni": "",
                "p_value_bh_fdr": "",
                **outcome,
            })

    apply_multiple_testing_corrections(results)
    return results


def coeff_bin_label(coeff_index, bin_size):
    start = (coeff_index // bin_size) * bin_size
    end = start + bin_size
    return f"{start}-{end}"


def run_first_coeff_bins_test(input_file, rows, method, reason_filter=None, bin_size=256):
    """
    Run binned first-rejecting-coefficient distribution tests by key.

    For each selected rejection reason, group coefficient indices into fixed-size
    bins, build a key-by-bin contingency table from first-rejecting-coefficient
    counts, and pass it to run_contingency_test to check whether the binned 
    coefficient distribution differs between keys.

                0-256   256-512   512-768   ...
        key 0     20       15        12
        key 1     10       25        14
        key 2     18       11        21

    """
    results = []

    reasons = sorted({
        row["reason"]
        for row in rows
        if row["reason"] in FIRST_COEFF_REASONS
        and (reason_filter is None or row["reason"] == reason_filter)
    })

    for reason in reasons:
        key_ids = sorted({
            row["key_id"]
            for row in rows
            if row["reason"] == reason
        })

        bin_labels = sorted({
            coeff_bin_label(row["coeff_index"], bin_size)
            for row in rows
            if row["reason"] == reason
        }, key=lambda label: int(label.split("-")[0]))

        by_key_bin = {
            (key_id, bin_label): 0
            for key_id in key_ids
            for bin_label in bin_labels
        }

        total_signatures_by_key = {}

        for row in rows:
            if row["reason"] != reason:
                continue

            key_id = row["key_id"]
            bin_label = coeff_bin_label(row["coeff_index"], bin_size)

            by_key_bin[(key_id, bin_label)] += row["count"]
            total_signatures_by_key[key_id] = row["total_signatures"]

        table_rows = []
        for key_id in key_ids:
            table_rows.append({
                "key_id": key_id,
                **{
                    bin_label: by_key_bin[(key_id, bin_label)]
                    for bin_label in bin_labels
                },
            })
        
        table = build_contingency_table(table_rows, bin_labels)
        outcomes = run_contingency_test(table, key_ids, method)

        for outcome in outcomes:
            results.append({
                "test": "first_coeff_bin_distribution_by_key",
                "reason": reason,
                "coeff_index": "",
                "total_count": int(table.sum()),
                "total_denominator": int(table.sum()),
                "total_signatures": sum(total_signatures_by_key.values()),
                "input_file": input_file,
                "p_value_bonferroni": "",
                "p_value_bh_fdr": "",
                **outcome,
                "notes": ";".join(
                    part for part in [
                        outcome.get("notes", ""),
                        f"bin_size={bin_size}",
                        f"n_bins={len(bin_labels)}",
                    ]
                    if part
                ),
            })

    apply_multiple_testing_corrections(results)
    return results


def apply_multiple_testing_corrections(results):
    runnable = [
        r for r in results
        if r.get("p_value", "") != ""
        and not str(r.get("notes", "")).startswith("skipped")
    ]
    if not runnable:
        return

    m = len(runnable)
    p_values = np.array([float(r["p_value"]) for r in runnable], dtype=float)

    for result, adjusted in zip(runnable, np.minimum(1.0, p_values * m)):
        result["p_value_bonferroni"] = float(adjusted)

    order = np.argsort(p_values)
    sorted_p = p_values[order]
    bh_adjusted = np.empty(m, dtype=float)
    prev = 1.0
    for i in range(m - 1, -1, -1):
        rank = i + 1
        prev = min(prev, sorted_p[i] * m / rank)
        bh_adjusted[i] = prev

    inverse = np.empty(m, dtype=int)
    inverse[order] = np.arange(m)
    for result, idx in zip(runnable, inverse):
        result["p_value_bh_fdr"] = float(bh_adjusted[idx])


def format_value(value):
    if value == "" or value is None:
        return ""
    if isinstance(value, float):
        return repr(float(value))
    return str(value)


def format_p_value(p_value):
    if p_value == "" or p_value is None:
        return ""
    p_value = float(p_value)
    if p_value < 1e-4:
        return f"{p_value:.4e}"
    return f"{p_value:.6f}"


def result_p_value(result):
    if result.get("p_value") == "" or result.get("p_value") is None:
        return None
    return float(result["p_value"])


def write_single_results(path, results):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", newline="") as out_fd:
        writer = csv.writer(out_fd)
        writer.writerow(SINGLE_TABLE_HEADER)
        for result in results:
            writer.writerow([
                result.get("test", ""),
                result.get("input_file", ""),
                result.get("method", ""),
                result.get("n_keys", ""),
                result.get("key_id_a", ""),
                result.get("key_id_b", ""),
                result.get("table_shape", ""),
                result.get("total_observations", ""),
                result.get("total_signatures", ""),
                format_value(result.get("statistic", "")),
                format_value(result.get("p_value", "")),
                format_value(result.get("dof", "")),
                format_value(result.get("p_value_bonferroni", "")),
                format_value(result.get("p_value_bh_fdr", "")),
                result.get("notes", ""),
            ])


def write_first_coeff_results(path, results):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", newline="") as out_fd:
        writer = csv.writer(out_fd)
        writer.writerow(FIRST_COEFF_HEADER)
        for result in results:
            writer.writerow([
                result.get("test", ""),
                result.get("reason", ""),
                result.get("coeff_index", ""),
                result.get("method", ""),
                result.get("n_keys", ""),
                result.get("key_id_a", ""),
                result.get("key_id_b", ""),
                result.get("table_shape", ""),
                result.get("total_observations", ""),
                result.get("total_signatures", ""),
                format_value(result.get("statistic", "")),
                format_value(result.get("p_value", "")),
                format_value(result.get("dof", "")),
                result.get("total_count", ""),
                result.get("total_denominator", ""),
                format_value(result.get("p_value_bonferroni", "")),
                format_value(result.get("p_value_bh_fdr", "")),
                result.get("notes", ""),
            ])


def write_blocked_result(path, result):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", newline="") as out_fd:
        writer = csv.writer(out_fd)
        writer.writerow(BLOCKED_TEST_HEADER)
        writer.writerow([
            result.get("test", ""),
            result.get("input_file", ""),
            result.get("method", ""),
            result.get("n_keys", ""),
            result.get("n_blocks", ""),
            result.get("table_shape", ""),
            result.get("total_observations", ""),
            format_value(result.get("statistic", "")),
            format_value(result.get("p_value", "")),
            format_value(result.get("dof", "")),
            result.get("notes", ""),
        ])


def run_test(test_name, input_path, method, reason=None, coeff_index=None, bin_size=256):
    input_path = Path(input_path)
    input_file = str(input_path)

    if test_name == "overall-rejection":
        rows = load_aggregated_csv(
            input_path,
            ["key_id", "total_signatures", "accepted_attempts", "rejected_attempts"],
        )
        results = run_single_table_test(
            "overall_rejection_by_key",
            input_file,
            rows,
            ["accepted_attempts", "rejected_attempts"],
            "key_id",
            method,
        )
        apply_multiple_testing_corrections(results)
        return results

    if test_name == "message-rejection":
        rows = load_aggregated_csv(
            input_path,
            ["key_id", "total_signatures", "clean_signatures", "signatures_with_rejection"],
        )
        results = run_single_table_test(
            "message_rejection_by_key",
            input_file,
            rows,
            ["clean_signatures", "signatures_with_rejection"],
            "key_id",
            method,
        )
        apply_multiple_testing_corrections(results)
        return results

    if test_name == "reason-vs-other":
        if reason is None:
            error("--reason is required for reason-vs-other test")
        rows = load_aggregated_csv(
            input_path,
            ["key_id", "total_signatures", f"{reason}_rejections", f"non_{reason}_attempts"],
        )
        results = run_single_table_test(
            f"{reason}_rejection_by_key",
            input_file,
            rows,
            [f"{reason}_rejections", f"non_{reason}_attempts"],
            "key_id",
            method,
        )
        apply_multiple_testing_corrections(results)
        return results

    if test_name == "reason-distribution":
        rows = load_aggregated_csv(
            input_path,
            [
                "key_id", "total_signatures",
                "z_rejections", "r0_rejections", "ct0_rejections", "hint_rejections",
            ],
        )
        if method == "binom":
            error("binomtest does not apply to reason-distribution (4 reason columns); use chi2 or fisher")
        results = run_single_table_test(
            "rejection_reason_by_key",
            input_file,
            rows,
            ["z_rejections", "r0_rejections", "ct0_rejections", "hint_rejections"],
            "key_id",
            method,
        )
        apply_multiple_testing_corrections(results)
        return results

    if test_name == "first-coeff":
        rows = load_aggregated_csv(
            input_path,
            [
                "key_id", "reason", "coeff_index", "count",
                "total_rejections_for_reason", "total_signatures",
            ],
        )
        return run_first_coeff_test(
            input_file, rows, method,
            reason_filter=reason, coeff_filter=coeff_index,
        )

    if test_name == "first-coeff-bins":
        rows = load_aggregated_csv(
            input_path,
            [
                "key_id", "reason", "coeff_index", "count",
                "total_rejections_for_reason", "total_signatures",
            ],
        )
        return run_first_coeff_bins_test(
            input_file, rows, method,
            reason_filter=reason, 
            bin_size=bin_size,
        )

    if test_name == "sum-first-bad-coeff":
        if method == "binom":
            error("binomtest does not apply to sum-first-bad-coeff (Friedman blocked test)")
        rows = load_blocked_measurements(input_path)
        return [run_friedman_blocked_test(input_file, rows, "sum_first_bad_coeff_by_key")]

    error(f"unknown test: {test_name}")


class BatchAnalysis:
    def __init__(self, output_dir, method="auto", alpha=0.01, verbose=False, summary_only=False):
        self.output = Path(output_dir)
        self.results_dir = self.output / "analysis_results"
        self.method = method
        self.alpha = alpha
        self.verbose = verbose
        self.summary_only = summary_only
        self.metadata = {"total_signatures": 0, "total_rejections": 0}

    def input_path(self, name):
        return self.output / INPUT_FILES[name]

    def result_path(self, filename):
        return self.results_dir / filename

    def load_metadata(self):
        path = self.input_path("overall_rejection")
        if not path.exists():
            return
        rows = load_aggregated_csv(
            path,
            ["key_id", "total_signatures", "accepted_attempts", "rejected_attempts"],
        )
        self.metadata["total_signatures"] = sum_total_signatures(rows)
        self.metadata["total_rejections"] = sum(row["rejected_attempts"] for row in rows)

    def generate_report(self):
        if not self.output.exists():
            error(f"output directory does not exist: {self.output}")

        self.results_dir.mkdir(parents=True, exist_ok=True)
        self.load_metadata()

        single_results = []
        single_results.extend(run_test(
            "overall-rejection", self.input_path("overall_rejection"), self.method,
        ))
        single_results.extend(run_test(
            "message-rejection", self.input_path("message_rejection"), self.method,
        ))
        single_results.extend(run_test(
            "reason-distribution", self.input_path("reason_distribution"), self.method,
        ))

        for reason in REASONS:
            path = self.output / f"test_{reason}_rejection_by_key.csv"
            if path.exists():
                single_results.extend(run_test(
                    "reason-vs-other", path, self.method, reason=reason,
                ))

        blocked_results = run_test(
            "sum-first-bad-coeff",
            self.input_path("sum_first_bad_coeff"),
            self.method,
        )

        coeff_path = self.input_path("first_coeff")
        if coeff_path.exists():
            first_coeff_results = run_test(
                "first-coeff", coeff_path, self.method,
            )
            first_coeff_bin_results = run_test(
                "first-coeff-bins", coeff_path, "chi2",
            )
        else:
            first_coeff_results = []
            first_coeff_bin_results = []
            if self.verbose:
                print(f"[i] Skipping first-coeff tests; {coeff_path} not found", file=sys.stderr)

        write_single_results(self.result_path("single_table_results.csv"), single_results)
        self._write_per_test_results(single_results)
        blocked_result = blocked_results[0]
        write_blocked_result(self.result_path("blocked_results.csv"), blocked_result)
        write_blocked_result(
            self.result_path("sum_first_bad_coeff_results.csv"), blocked_result,
        )
        write_first_coeff_results(
            self.result_path("first_rejecting_coeff_results.csv"), first_coeff_results,
        )
        write_first_coeff_results(
            self.result_path("first_coeff_bin_results.csv"), first_coeff_bin_results,
        )
        self.write_report_csv(single_results, blocked_results, first_coeff_results + first_coeff_bin_results)
        self.write_summary(single_results, blocked_results, first_coeff_results + first_coeff_bin_results)

        if not self.summary_only:
            self.print_results(single_results, blocked_results, first_coeff_results + first_coeff_bin_results)

        print(f"Analysis written to {self.results_dir}", file=sys.stderr)
        return 0

    def _write_per_test_results(self, single_results):
        by_test = {}
        for result in single_results:
            by_test.setdefault(result["test"], []).append(result)

        output_names = {
            "overall_rejection_by_key": "overall_rejection_results.csv",
            "message_rejection_by_key": "message_rejection_results.csv",
            "rejection_reason_by_key": "rejection_reason_results.csv",
            "z_rejection_by_key": "z_rejection_results.csv",
            "r0_rejection_by_key": "r0_rejection_results.csv",
            "ct0_rejection_by_key": "ct0_rejection_results.csv",
            "hint_rejection_by_key": "hint_rejection_results.csv",  
        }
        for test_name, results in by_test.items():
            filename = output_names.get(test_name)
            if filename:
                write_single_results(self.result_path(filename), results)

    def write_report_csv(self, single_results, blocked_results, first_coeff_results):
        with open(self.result_path("report.csv"), "w", newline="") as out_fd:
            writer = csv.writer(out_fd)
            writer.writerow(REPORT_HEADER)
            for result in single_results + blocked_results + first_coeff_results:
                writer.writerow(self.report_row(result))

    def report_row(self, result):
        return [
            result.get("test", ""),
            result.get("reason", ""),
            result.get("coeff_index", ""),
            result.get("method", ""),
            result.get("n_keys", ""),
            result.get("key_id_a", ""),
            result.get("key_id_b", ""),
            result.get("n_blocks", ""),
            result.get("table_shape", ""),
            result.get("total_observations", ""),
            result.get("total_signatures", ""),
            format_value(result.get("statistic", "")),
            format_value(result.get("p_value", "")),
            format_value(result.get("dof", "")),
            format_value(result.get("p_value_bonferroni", "")),
            format_value(result.get("p_value_bh_fdr", "")),
            result.get("notes", ""),
        ]

    def write_summary(self, single_results, blocked_results, first_coeff_results):
        all_results = single_results + blocked_results + first_coeff_results
        usable = [r for r in all_results if result_p_value(r) is not None]
        significant = [r for r in usable if result_p_value(r) < self.alpha]
        min_result = min(usable, key=result_p_value) if usable else None

        with open(self.result_path("report.txt"), "w") as out_fd:
            out_fd.write("analyze_rejections.py analysis\n")
            out_fd.write(f"Input directory: {self.output}\n")
            out_fd.write(f"Alpha: {self.alpha}\n")
            out_fd.write(f"Total signatures: {self.metadata['total_signatures']}\n")
            out_fd.write(f"Total rejections: {self.metadata['total_rejections']}\n")
            out_fd.write(f"Tests with p-values: {len(usable)}\n")
            out_fd.write(f"Significant tests: {len(significant)}\n")

            if min_result is not None:
                out_fd.write(
                    f"Smallest p-value: {format_p_value(result_p_value(min_result))} "
                    f"({min_result.get('test', '')})\n"
                )

            if significant:
                out_fd.write("\nResults below alpha:\n")
                for result in significant:
                    label = result.get("test", "")
                    if result.get("reason", "") != "":
                        label += f" / {result['reason']}"
                    if result.get("coeff_index", "") != "":
                        label += f" / coeff {result['coeff_index']}"
                    if result.get("key_id_a", "") != "":
                        label += f" / keys {result['key_id_a']}-{result['key_id_b']}"
                    out_fd.write(
                        f"  {label}: p={format_p_value(result_p_value(result))}\n"
                    )
            else:
                out_fd.write("\nNo test produced a p-value below alpha.\n")

            out_fd.write("\nDetailed CSV report: report.csv")

    def print_results(self, single_results, blocked_results, first_coeff_results):
        for result in single_results + blocked_results:
            print(f"Test: {result['test']}", file=sys.stderr)
            if result.get("method", "") == "":
                print("Result: SKIPPED", file=sys.stderr)
                print(f"Notes: {result.get('notes', '')}", file=sys.stderr)
                print(file=sys.stderr)
                continue
            print(f"Method: {result['method']}", file=sys.stderr)
            if result.get("key_id_a", "") != "":
                print(f"Key pair: {result['key_id_a']} vs {result['key_id_b']}", file=sys.stderr)
            if result.get("n_blocks", "") != "":
                print(f"Blocks: {result['n_blocks']}", file=sys.stderr)
            print(f"Table: {result['table_shape']} ({result['n_keys']} keys)", file=sys.stderr)
            print(f"Observations: {result['total_observations']}", file=sys.stderr)
            print(f"p-value: {format_p_value(result['p_value'])}", file=sys.stderr)
            if result.get("notes"):
                print(f"Notes: {result['notes']}", file=sys.stderr)
            print(file=sys.stderr)

        per_coeff_results = [
            r for r in first_coeff_results
            if r.get("test") == "first_rejecting_coeff_by_key"
        ]
        binned_results = [
            r for r in first_coeff_results
            if r.get("test") == "first_coeff_bin_distribution_by_key"
        ]

        for result in binned_results:
            label = result["test"]
            if result.get("reason", "") != "":
                label += f" / {result['reason']}"
            print(f"Test: {label}", file=sys.stderr)
            if result.get("method", "") == "":
                print("Result: SKIPPED", file=sys.stderr)
                print(f"Notes: {result.get('notes', '')}", file=sys.stderr)
                print(file=sys.stderr)
                continue
            print(f"Method: {result['method']}", file=sys.stderr)
            print(f"Table: {result['table_shape']} ({result['n_keys']} keys)", file=sys.stderr)
            print(f"Observations: {result['total_observations']}", file=sys.stderr)
            print(f"p-value: {format_p_value(result['p_value'])}", file=sys.stderr)
            if result.get("notes"):
                print(f"Notes: {result['notes']}", file=sys.stderr)
            print(file=sys.stderr)

        if per_coeff_results:
            usable = [r for r in per_coeff_results if result_p_value(r) is not None]
            print("Test: first_rejecting_coeff_by_key", file=sys.stderr)
            print(f"Coefficient tests: {len(per_coeff_results)}", file=sys.stderr)
            if usable:
                best = min(usable, key=result_p_value)
                print(
                    f"Smallest p-value: {format_p_value(result_p_value(best))} "
                    f"({best['reason']}, coeff {best['coeff_index']})",
                    file=sys.stderr,
                )
            print(file=sys.stderr)


def main():
    args = parse_args()

    if args.all:
        if not args.output:
            error("--output is required with --all")
        analysis = BatchAnalysis(
            output_dir=args.output,
            method=args.method,
            alpha=args.alpha,
            verbose=args.verbose,
            summary_only=args.summary_only,
        )
        return analysis.generate_report()

    if not args.input or not args.out:
        error("--input and --out are required for single-test mode")

    if args.test == "reason-vs-other" and args.reason is None:
        error("--reason is required for reason-vs-other test")

    results = run_test(
        args.test,
        args.input,
        args.method,
        reason=args.reason,
        coeff_index=args.coeff_index,
        bin_size=args.bin_size,
    )

    if args.test == "first-coeff":
        write_first_coeff_results(args.out, results)
    elif args.test == "sum-first-bad-coeff":
        write_blocked_result(args.out, results[0])
    else:
        write_single_results(args.out, results)

    return 0


if __name__ == "__main__":
    sys.exit(main())
