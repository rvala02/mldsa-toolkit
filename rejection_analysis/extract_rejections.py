"""
Extract test-specific rejection CSV files from raw harness output.

Usage:
    python extract_rejections.py \\
        --input raw_rejections.csv \\
        --out-dir extracted/
"""

import argparse
import csv
import sys
from pathlib import Path

MAIN_COLUMNS = [
    "key_id",
    "message_id",
    "global_message_id",
    "attempts",
    "z_rejections",
    "r0_rejections",
    "ct0_rejections",
    "hint_rejections",
    "total_rejections",
    "sum_first_bad_coeff",
    "first_rejection_reason",
    "accepted",
]

COEFF_COLUMNS = [
    "key_id",
    "message_id",
    "global_message_id",
    "attempt_id",
    "reason",
    "first_bad_coeff",
    "num_bad_coeffs",
]

FIRST_REJECTION_REASON = {"none", "z", "r0", "ct0", "hint"}
COEFF_REASONS = {"z", "r0", "ct0", "hint"}
COEFF_OUTPUT_REASONS = {"z", "r0", "ct0"}

COEFF_OUTPUT_FILE = "test_first_rejecting_coeff_by_key.csv"
SUM_FIRST_BAD_COEFF_FILE = "test_sum_first_bad_coeff_by_key.csv"

PROGRESS_INTERVAL = 1000


def report_progress(count, last_reported, label):
    while last_reported + PROGRESS_INTERVAL <= count:
        last_reported += PROGRESS_INTERVAL
        print(f"Processed {last_reported} {label}...", file=sys.stderr)
    return last_reported


def report_final_progress(count, last_reported, label):
    if count > last_reported:
        print(f"Processed {count} {label}...", file=sys.stderr)


def parse_args():
    parser = argparse.ArgumentParser(
        description="Extract test-specific rejection CSV files"
    )
    parser.add_argument(
        "--input", "-i",
        required=True,
        help="Main per-message rejection CSV",
    )
    parser.add_argument(
        "--out-dir", "-o",
        required=True,
        help="Output directory",
    )
    parser.add_argument(
        "--coeff-input", "-c",
        default=None,
        help="Optional coefficient CSV",
    )
    return parser.parse_args()


def error(msg):
    print(f"ERROR: {msg}", file=sys.stderr)
    sys.exit(1)


def parse_int(value, field, row_num):
    try:
        return int(value)
    except ValueError:
        error(f"row {row_num}: {field} must be an integer, got {value!r}")


def validate_columns(fieldnames, required, label):
    if fieldnames is None:
        error(f"{label} file is empty")
    missing = [col for col in required if col not in fieldnames]
    if missing:
        error(f"{label} file missing required columns: {', '.join(missing)}")


def new_key_stats():
    return {
        "total_signatures": 0,
        "attempts": 0,
        "total_rejections": 0,
        "z_rejections": 0,
        "r0_rejections": 0,
        "ct0_rejections": 0,
        "hint_rejections": 0,
        "clean_signatures": 0,
        "signatures_with_rejection": 0,
    }


def validate_main_row(row, row_num):
    parsed = {}
    for col in MAIN_COLUMNS:
        if col == "first_rejection_reason":
            parsed[col] = row[col]
            continue
        parsed[col] = parse_int(row[col], col, row_num)

    attempts = parsed["attempts"]
    total_rejections = parsed["total_rejections"]
    accepted = parsed["accepted"]
    first_reason = parsed["first_rejection_reason"]

    if attempts < 1:
        error(f"row {row_num}: attempts must be >= 1, got {attempts}")
    if accepted != 1:
        error(f"row {row_num}: accepted must be 1, got {accepted}")
    if total_rejections != attempts - 1:
        error(
            f"row {row_num}: total_rejections ({total_rejections}) "
            f"must equal attempts - 1 ({attempts - 1})"
        )

    reason_sum = (
        parsed["z_rejections"]
        + parsed["r0_rejections"]
        + parsed["ct0_rejections"]
        + parsed["hint_rejections"]
    )
    if total_rejections != reason_sum:
        error(
            f"row {row_num}: total_rejections ({total_rejections}) "
            f"must equal sum of per-reason rejections ({reason_sum})"
        )

    if first_reason not in FIRST_REJECTION_REASON:
        error(f"row {row_num}: invalid first_rejection_reason {first_reason!r}")
    if total_rejections == 0 and first_reason != "none":
        error(f"row {row_num}: first_rejection_reason must be 'none' when total_rejections is 0")
    if total_rejections > 0 and first_reason == "none":
        error(f"row {row_num}: first_rejection_reason must not be 'none' when total_rejections > 0")

    if parsed["sum_first_bad_coeff"] < 0:
        error(
            f"row {row_num}: sum_first_bad_coeff must be >= 0, "
            f"got {parsed['sum_first_bad_coeff']}"
        )

    return parsed


def update_key_stats(stats, row):
    stats["total_signatures"] += 1
    stats["attempts"] += row["attempts"]
    stats["total_rejections"] += row["total_rejections"]
    stats["z_rejections"] += row["z_rejections"]
    stats["r0_rejections"] += row["r0_rejections"]
    stats["ct0_rejections"] += row["ct0_rejections"]
    stats["hint_rejections"] += row["hint_rejections"]
    if row["total_rejections"] == 0:
        stats["clean_signatures"] += 1
    else:
        stats["signatures_with_rejection"] += 1


def write_csv(path, header, rows):
    with open(path, "w", newline="") as out_fd:
        writer = csv.writer(out_fd)
        writer.writerow(header)
        writer.writerows(rows)


def write_aggregated_files(by_key, out_dir):
    written = []
    key_ids = sorted(by_key)

    overall_rows = []
    message_rows = []
    reason_rows = []

    for key_id in key_ids:
        s = by_key[key_id]
        ts = s["total_signatures"]
        accepted = ts
        rejected = s["total_rejections"]
        total_attempts = s["attempts"]

        overall_rows.append([key_id, ts, accepted, rejected, total_attempts])
        message_rows.append([
            key_id, ts, s["clean_signatures"], s["signatures_with_rejection"],
        ])
        reason_rows.append([
            key_id, ts, s["total_rejections"],
            s["z_rejections"], s["r0_rejections"],
            s["ct0_rejections"], s["hint_rejections"],
        ])

    specs = [
        (
            "test_overall_rejection_by_key.csv",
            ["key_id", "total_signatures", "accepted_attempts",
             "rejected_attempts", "total_attempts"],
            overall_rows,
        ),
        (
            "test_message_rejection_by_key.csv",
            ["key_id", "total_signatures", "clean_signatures",
             "signatures_with_rejection"],
            message_rows,
        ),
        (
            "test_rejection_reason_by_key.csv",
            ["key_id", "total_signatures", "total_rejections",
             "z_rejections", "r0_rejections", "ct0_rejections", "hint_rejections"],
            reason_rows,
        ),
    ]

    for reason in ("z", "r0", "ct0", "hint"):
        rows = []
        for key_id in key_ids:
            s = by_key[key_id]
            ts = s["total_signatures"]
            total_attempts = s["attempts"]
            reason_count = s[f"{reason}_rejections"]
            non_reason = total_attempts - reason_count
            rows.append([key_id, ts, reason_count, non_reason, total_attempts])
        specs.append((
            f"test_{reason}_rejection_by_key.csv",
            ["key_id", "total_signatures", f"{reason}_rejections",
             f"non_{reason}_attempts", "total_attempts"],
            rows,
        ))

    for filename, header, rows in specs:
        write_csv(out_dir / filename, header, rows)
        written.append(filename)

    return written


def stream_main_csv(path, by_key, sum_writer):
    if not path.exists():
        error(f"input file does not exist: {path}")

    row_count = 0
    last_reported = 0
    with open(path, newline="") as in_fd:
        reader = csv.DictReader(in_fd)
        validate_columns(reader.fieldnames, MAIN_COLUMNS, "input")

        for row_num, row in enumerate(reader, start=2):
            parsed = validate_main_row(row, row_num)
            key_id = parsed["key_id"]

            if key_id not in by_key:
                by_key[key_id] = new_key_stats()

            update_key_stats(by_key[key_id], parsed)
            sum_writer.writerow([
                parsed["message_id"],
                key_id,
                parsed["sum_first_bad_coeff"],
            ])
            row_count += 1
            last_reported = report_progress(row_count, last_reported, "raw rows")

    if row_count == 0:
        error("input file contains no data rows")

    report_final_progress(row_count, last_reported, "raw rows")
    return row_count


def validate_coeff_row(row, row_num):
    parsed = {
        "key_id": parse_int(row["key_id"], "key_id", row_num),
        "message_id": parse_int(row["message_id"], "message_id", row_num),
        "global_message_id": parse_int(row["global_message_id"], "global_message_id", row_num),
        "attempt_id": parse_int(row["attempt_id"], "attempt_id", row_num),
        "reason": row["reason"],
        "first_bad_coeff": parse_int(row["first_bad_coeff"], "first_bad_coeff", row_num),
        "num_bad_coeffs": parse_int(row["num_bad_coeffs"], "num_bad_coeffs", row_num),
    }

    if parsed["attempt_id"] < 0:
        error(f"row {row_num}: attempt_id must be >= 0, got {parsed['attempt_id']}")
    if parsed["num_bad_coeffs"] < 0:
        error(f"row {row_num}: num_bad_coeffs must be >= 0, got {parsed['num_bad_coeffs']}")
    if parsed["reason"] not in COEFF_REASONS:
        error(f"row {row_num}: invalid reason {parsed['reason']!r}")
    if parsed["reason"] == "hint" and parsed["first_bad_coeff"] != -1:
        error(f"row {row_num}: hint rows must have first_bad_coeff = -1")
    elif parsed["reason"] != "hint" and parsed["first_bad_coeff"] < 0:
        error(
            f"row {row_num}: first_bad_coeff must be >= 0 for "
            f"reason {parsed['reason']!r}, got {parsed['first_bad_coeff']}"
        )

    return parsed


def aggregate_coeff_csv(path, by_key, out_path):
    if not path.exists():
        error(f"coefficient input file does not exist: {path}")

    counts = {}
    row_count = 0
    last_reported = 0

    with open(path, newline="") as in_fd:
        reader = csv.DictReader(in_fd)
        validate_columns(reader.fieldnames, COEFF_COLUMNS, "coefficient input")

        for row_num, row in enumerate(reader, start=2):
            parsed = validate_coeff_row(row, row_num)
            if parsed["reason"] not in COEFF_OUTPUT_REASONS:
                row_count += 1
                continue

            key = (parsed["key_id"], parsed["reason"], parsed["first_bad_coeff"])
            counts[key] = counts.get(key, 0) + 1
            row_count += 1
            last_reported = report_progress(row_count, last_reported, "coefficient rows")

    report_final_progress(row_count, last_reported, "coefficient rows")

    rows = []
    for (key_id, reason, coeff_index), count in sorted(counts.items()):
        ts = by_key[key_id]["total_signatures"]
        denom = by_key[key_id][f"{reason}_rejections"]
        rows.append([key_id, reason, coeff_index, count, denom, ts])

    write_csv(
        out_path,
        ["key_id", "reason", "coeff_index", "count",
         "total_rejections_for_reason", "total_signatures"],
        rows,
    )
    return row_count


def main():
    args = parse_args()

    input_path = Path(args.input)
    out_dir = Path(args.out_dir)
    coeff_path = Path(args.coeff_input) if args.coeff_input else None

    out_dir.mkdir(parents=True, exist_ok=True)

    by_key = {}
    sum_path = out_dir / SUM_FIRST_BAD_COEFF_FILE
    with open(sum_path, "w", newline="") as sum_fd:
        sum_writer = csv.writer(sum_fd)
        sum_writer.writerow(["block_id", "key_id", "value"])
        total_signatures = stream_main_csv(input_path, by_key, sum_writer)

    written = write_aggregated_files(by_key, out_dir)
    written.append(SUM_FIRST_BAD_COEFF_FILE)

    if coeff_path is not None:
        aggregate_coeff_csv(coeff_path, by_key, out_dir / COEFF_OUTPUT_FILE)
        written.append(COEFF_OUTPUT_FILE)

    num_keys = len(by_key)
    total_attempts = sum(s["attempts"] for s in by_key.values())
    total_rejections = sum(s["total_rejections"] for s in by_key.values())

    print(f"Processed raw rows: {total_signatures}", file=sys.stderr)
    print(f"Keys: {num_keys}", file=sys.stderr)
    print(f"Total signatures: {total_signatures}", file=sys.stderr)
    print(f"Total attempts: {total_attempts}", file=sys.stderr)
    print(f"Total rejections: {total_rejections}", file=sys.stderr)
    print("Output files:", file=sys.stderr)
    for filename in written:
        print(f"    {out_dir / filename}", file=sys.stderr)


if __name__ == "__main__":
    main()
