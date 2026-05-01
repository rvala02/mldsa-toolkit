"""
Output:
- schedule.bin: binary file with raw_sk_bytes (PEM) or 32-byte seeds
- log.csv: CSV file with key order per round
Usage:
    python generate_schedule.py -k keys_dir -o schedule.bin -l log.csv -s 44|65|87 -r N
    python generate_schedule.py ... -f seed   # key_XX/seed.bin (32 bytes each)
"""

import sys
import argparse
import csv
import random
from pathlib import Path
from dilithium_py.ml_dsa.pkcs import sk_from_pem

SK_SIZES = {
    "44": 2560,
    "65": 4032,
    "87": 4896,
}

SEED_SIZE = 32


def load_keys(keys_dir, scheme, key_format):
    """
    Load secret key material from key_XX/ directories.

    PEM (--format pem): key_XX/sk.pem → semi-expanded SK (scheme-sized).
    Seed (--format seed): key_XX/seed.bin → 32-byte seed (same for all schemes).
    """
    keys_dir = Path(keys_dir)
    keys = {}

    if key_format == "pem":
        expected_size = SK_SIZES[scheme]
        sk_name = "sk.pem"
    else:
        expected_size = SEED_SIZE
        sk_name = "seed.bin"

    for key_dir in sorted(keys_dir.iterdir()):
        if key_dir.is_dir() and key_dir.name.startswith("key_"):
            sk_file = key_dir / sk_name
            if not sk_file.exists():
                continue

            try:
                key_id = int(key_dir.name.split("_")[1])
            except ValueError:
                continue

            raw = sk_file.read_bytes()

            if key_format == "pem":
                _, sk_bytes, _, _ = sk_from_pem(raw)
            else:
                sk_bytes = raw

            if len(sk_bytes) != expected_size:
                print(
                    f"ERROR: key_{key_id:02d} has wrong size: "
                    f"{len(sk_bytes)} != {expected_size}"
                )
                sys.exit(1)

            keys[key_id] = sk_bytes

    return keys


def parse_args():
    parser = argparse.ArgumentParser(
        description="Generate schedule for ML-DSA timing analysis"
    )
    parser.add_argument(
        "--keys", "-k",
        type=str,
        required=True,
        help="Directory containing key_XX/sk.pem (pem) or key_XX/seed.bin (seed)",
    )
    parser.add_argument(
        "--output", "-o",
        type=str,
        default="schedule.bin",
        help="Output schedule file (default: schedule.bin)",
    )
    parser.add_argument(
        "--log", "-l",
        type=str,
        default="log.csv",
        help="Output log file for analysis (default: log.csv)",
    )
    parser.add_argument(
        "--scheme", "-s",
        type=str,
        required=True,
        choices=["44", "65", "87"],
        help="ML-DSA scheme: 44, 65, or 87",
    )
    parser.add_argument(
        "--rounds", "-r",
        type=int,
        required=True,
        help="Number of signing rounds",
    )
    parser.add_argument(
        "--format", "-f",
        type=str,
        choices=["pem", "seed"],
        default="pem",
        help="Key material: pem (sk.pem, expanded SK) or seed (seed.bin, 32 bytes)",
    )

    return parser.parse_args()


if __name__ == '__main__':
    args = parse_args()

    keys = load_keys(args.keys, args.scheme, args.format)
    key_ids = sorted(keys.keys())
    num_keys = len(key_ids)

    if num_keys == 0:
        print("ERROR: No keys found in directory")
        sys.exit(1)

    class_names = [f"key_{kid:02d}" for kid in key_ids]

    with open(args.output, "wb") as sched_fd:
        with open(args.log, "w", newline='') as log_fd:
            writer = csv.writer(log_fd)
            writer.writerow(class_names)

            for _ in range(args.rounds):
                order = list(range(num_keys))
                random.shuffle(order)

                writer.writerow(order)

                for idx in order:
                    key_id = key_ids[idx]
                    sched_fd.write(keys[key_id])

    print("done")
