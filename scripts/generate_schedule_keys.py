"""
Usage:
    python generate_schedule_keys.py -k keys_out -c clean|early -s 44|65|87 -r N -o schedule.bin -d messages.bin -l log.csv -f pem|seed

schedule.bin: expanded SK from key_XX/sk.pem (--format pem) or 32-byte seed.bin (--format seed).
"""
import argparse
import csv
import random
import sys
from pathlib import Path

from dilithium_py.ml_dsa.pkcs import sk_from_pem

SK_SIZES = {
    "44": 2560,
    "65": 4032,
    "87": 4896,
}

SEED_SIZE = 32
MSG_SIZE = 32


def parse_args():
    p = argparse.ArgumentParser(
        description="Generate schedule + messages from per-key CSVs"
    )
    p.add_argument("-k", "--keys", required=True, help="keys_out directory")
    p.add_argument("-c", "--class", dest="cls", required=True,
                   choices=["clean", "early"],
                   help="Message class to schedule")
    p.add_argument("-s", "--scheme", required=True, choices=["44", "65", "87"])
    p.add_argument("-r", "--rounds", type=int, required=True)

    p.add_argument("-o", "--schedule", default="schedule.bin")
    p.add_argument("-d", "--messages", default="messages.bin")
    p.add_argument("-l", "--log", default="log.csv")
    p.add_argument(
        "--format", "-f",
        type=str,
        choices=["pem", "seed"],
        default="pem",
        help="Key material: pem (sk.pem, expanded SK) or seed (seed.bin, 32 bytes)",
    )

    return p.parse_args()


def main():
    args = parse_args()

    keys_dir = Path(args.keys)
    if args.format == "pem":
        expected_key_size = SK_SIZES[args.scheme]
        key_filename = "sk.pem"
    else:
        expected_key_size = SEED_SIZE
        key_filename = "seed.bin"

    keys = {}
    messages = {}

    for key_dir in sorted(keys_dir.iterdir()):
        if not key_dir.is_dir() or not key_dir.name.startswith("key_"):
            continue

        key_id = int(key_dir.name.split("_")[1])

        key_file = key_dir / key_filename
        if not key_file.exists():
            continue

        raw = key_file.read_bytes()
        if args.format == "pem":
            _, sk_bytes, _, _ = sk_from_pem(raw)
        else:
            sk_bytes = raw

        if len(sk_bytes) != expected_key_size:
            print(
                f"ERROR: key_{key_id:03d} has wrong size: "
                f"{len(sk_bytes)} != {expected_key_size}"
            )
            sys.exit(1)

        msg_csv = key_dir / f"{args.cls}.csv"
        if not msg_csv.exists():
            raise RuntimeError(f"{msg_csv} missing")

        msgs = []
        with msg_csv.open() as f:
            reader = csv.DictReader(f)
            for row in reader:
                msg = bytes.fromhex(row["msg_hex"])
                if len(msg) != MSG_SIZE:
                    raise ValueError("Bad message length")
                msgs.append(msg)

        if len(msgs) < args.rounds:
            raise RuntimeError(
                f"key_{key_id:03d} has only {len(msgs)} {args.cls} messages"
            )

        keys[key_id] = sk_bytes
        messages[key_id] = msgs

    key_ids = sorted(keys.keys())
    if not key_ids:
        print("ERROR: No keys found in directory")
        sys.exit(1)

    with open(args.schedule, "wb") as sched_fd, \
         open(args.messages, "wb") as msg_fd, \
         open(args.log, "w", newline="") as log_fd:

        writer = csv.writer(log_fd)
        writer.writerow([f"key_{kid:03d}" for kid in key_ids])

        for r in range(args.rounds):
            order = list(range(len(key_ids)))
            random.shuffle(order)
            writer.writerow(order)

            for idx in order:
                kid = key_ids[idx]
                sched_fd.write(keys[kid])
                msg_fd.write(messages[kid][r])

    total = args.rounds * len(key_ids)
    print(f"class        : {args.cls}")
    print(f"keys         : {len(key_ids)}")
    print(f"rounds/key   : {args.rounds}")
    print(f"total ops   : {total}")
    print(f"schedule.bin : {args.schedule}")
    print(f"messages.bin : {args.messages}")


if __name__ == "__main__":
    main()
