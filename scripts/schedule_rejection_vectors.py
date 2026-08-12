"""
Schedule ML-DSA rejection-count timing vectors for harness input.

Input layout:
    in_dir/
        class_00/
            keys.bin
            messages.bin
            signatures.bin
        class_01/
            keys.bin
            messages.bin
            signatures.bin
        ...

Output layout:
    out_dir/
        keys.bin
        messages.bin
        signatures.bin
        schedule.csv

For each round, the scheduler takes one record from each class and shuffles
the class order. The record index inside each class is the round number.

Example:
    python schedule_rejection_vectors.py \
        --in-dir vectors_mldsa44 \
        --out-dir scheduled_mldsa44 \
        --classes 20 \
        --rounds 10000 \
        --scheme 44
"""

import argparse
from ast import arg
import csv
from inspect import signature
import os
import random
import sys
from pathlib import Path

KEY_SIZE = 32
MSG_SIZE = 32
PROGRESS_INTERVAL = 1000

SIGNATURE_SIZES = {
    "44": 2420,
    "65": 3309,
    "87": 4627,
}

class ClassInput:
    def __init__(self, class_id, path, key_size, msg_size, sig_size):
        self.class_id = class_id
        self.path = path
        self.key_size = key_size
        self.msg_size = msg_size
        self.sig_size = sig_size

        self.keys_path = path / "keys.bin"
        self.messages_path = path / "messages.bin"
        self.signatures_path = path / "signatures.bin"

        self._validate_exists()
        self.count = self._validate_counts()

        self.keys_fd = open(self.keys_path, "rb")
        self.messages_fd = open(self.message_path, "rb")
        self.signatures_fd = open(self.signatures_path, "rb")
    
    def _validate_exists(self):
        for path in [self.keys_path, self.messages_path, self.signatures_path]:
            if not path.exists():
                error(f"missing input file: {path}")
    
    def _record_count(self, path, record_size):
        size = path.stat().st_size
        if size % record_size != 0:
            error(f"{path} size {size} is not divisible by record size {record_size}")
        return size // record_size
    
    def _validate_counts(self):
        counts = {
            "keys.bin": self._record_count(self.keys_path, self.key_size),
            "messages.bin": self._record_count(self.messages_path, self.msg_size),
            "sigantures.bin": self._record_count(self.signatures_path, self.sig_size),
        }

        unique_counts = set(counts.values())
        if len(unique_counts) != 1:
            error(f"inconsistent input counts in {self.path}: {counts}")
        
        return unique_counts.pop()
    
    def read_record(self, record_index):
        return (
            read_fixed_record(self.keys_fd, self.key_size, record_index, self.keys_path),
            read_fixed_record(self.messages_fd, self.msg_size, record_index, self.messages_path),
            read_fixed_record(self.signatures_fd, self.sig_size, record_index, self.signatures_path),
        )
    
    def close(self):
        self.keys_fd.close()
        self.messages_fd.close()
        self.signatures_fd.close()
    

def parse_args():
    parser = argparse.ArgumentParser(
        description="Schedule rejection-count vectors into randomized harness inputs."
    )
    parser.add_argument(
        "--in-dir", "-i",
        required=True,
        type=Path,
        help="Input directory containing class_XX subdirectories.",
    )
    parser.add_argument(
        "--out-dir", "-o",
        required=True,
        type=Path,
        help="Output directory for scheduled harness inputs.",
    )
    parser.add_argument(
        "--classes", "-c",
        type=int,
        default=20,
        help="Number of class_XX directories. Default: 20.",
    )
    parser.add_argument(
        "--rounds", "-r",
        type=int,
        required=True,
        help="Number of rounds to schedule. Each round uses one record per class.",
    )
    parser.add_argument(
        "--scheme", "-s",
        required=True,
        choices=["44", "65", "87"],
        help="ML-DSA scheme: 44, 65 or 87",
    )
    parser.add_argument(
        "--progress-interval", "-p",
        type=int,
        default=PROGRESS_INTERVAL,
        help=f"Print progress every N rounds. Default: {PROGRESS_INTERVAL}",
    )
    return parser.parse_args()


def error(msg):
    print(f"ERROR: {msg}")
    sys.exit(1)


def flush_outputs(*file_handles):
    for handle in file_handles:
        handle.flush()
        os.fsync(handle.fileno())


def read_fixed_record(file_handle, record_size, record_index, path):
    file_handle.seek(record_index * record_size)
    data = file_handle.read(record_size)
    if len(data) != record_size:
        error(
            f"failed to read record {record_index} from {path}: "
            f"expected {record_size} bytes, got {len(data)}"
        )
    return data


def ensure_output_is_clean(out_dir):
    existing = []
    for name in ["keys.bin", "messages.bin", "signatures.bin", "schedule.csv"]:
        path = out_dir / name
        if path.exists() and path.stat().st_size > 0:
            existing.append(path)
    
    if existing:
        error(
            "output files already exist; delete the output directory first: "
            + ", ".join(str(path) for path in existing)
        )


def open_class_inputs(in_dir, classes, key_size, msg_size, sig_size):
    inputs = []
    for class_id in range(classes):
        class_path = in_dir / f"class_{class_id:02d}"
        if not class_path.exists():
            error(f"missing class directory: {class_path}")
        inputs.append(
            ClassInput(
                class_id=class_id,
                path=class_path,
                key_size=key_size,
                msg_size=msg_size,
                sig_size=sig_size,
            )
        )
    return inputs


def validate_available_rounds(class_inputs, rounds):
    for class_input in class_inputs:
        if class_input.count < rounds:
            error(
                f"class_{class_input.class_id:02d} has only {class_input.count} "
                f"records, but --rounds requires {rounds}"
            )


def close_class_inputs(class_inputs):
    for class_input in class_inputs:
        class_input.close()


def schedule_vectors(args):
    if args.classes <= 1:
        error("--classes must be greater than 1")
    if args.rounds <= 0:
        error("--rounds must be positive")
    if args.progress_interval <= 0:
        error("--progress-interval must be positive")
    if not args.in_dir.exists():
        error(f"input directory does not exist: {args.in_dir}")
    
    args.out_dir.mkdir(parents=True, exist_ok=True)
    ensure_output_is_clean(args.out_dir)

    signature_size = SIGNATURE_SIZES[args.scheme]

    class_inputs = open_class_inputs(
        args.in_dir,
        args.classes,
        KEY_SIZE,
        MSG_SIZE,
        signature_size,
    )
    validate_available_rounds(class_inputs, args.rounds)

    keys_out_path = args.out_dir / "keys.bin"
    messages_out_path = args.out_dir / "messages.bin"
    signatures_out_path = args.out_dir / "signatures.bin"
    schedule_path = args.out_dir / "schedule.csv"

    scheduled_index = 0

    print(f"Input: {args.in_dir}")
    print(f"Output: {args.out_dir}")
    print(f"Classes: {args.classes}")
    print(f"Rounds: {args.rounds}")
    print(f"Scheme: ML-DSA-{args.scheme}")
    print(f"Signature size: {signature_size}")
    print(f"Total scheduled records: {args.classes * args.rounds}")   

    try:
        with open(keys_out_path, "wb") as keys_out, \
            open(messages_out_path, "wb") as messages_out, \
            open(signatures_out_path, "wb") as signatures_out, \
            open(schedule_path, "w", newline="") as schedule_fd:

            schedule_writer = csv.writer(schedule_fd)
            schedule_writer.writerow([
                "scheduled_index",
                "round_id",
                "position_in_round",
                "class_id",
                "class_record_index",
            ])

            for round_id in range(args.rounds):
                order = list(range(args.classes))
                random.shuffle(order)

                for position_in_round, class_id in enumerate(order):
                    class_record_index = round_id
                    seed, message, signature = class_inputs[class_id].read_record(
                        class_record_index
                    )

                    keys_out.write(seed)
                    messages_out.write(message)
                    signatures_out.write(signature)

                    schedule_writer.writerow([
                        scheduled_index,
                        round_id,
                        position_in_round,
                        class_id,
                        class_record_index,
                    ])

                    scheduled_index += 1
                
                if (round_id + 1) % args.progress_interval == 0:
                    flush_outputs(keys_out, messages_out, signatures_out, schedule_fd)
                    print(f"Scheduled {round_id + 1}/{args.rounds} rounds")
            
            flush_outputs(keys_out, messages_out, signatures_out, schedule_fd)
    
    finally:
        close_class_inputs(class_inputs)
    
    print(f"Scheduled {args.rounds}/{args.rounds} rounds")
    print(f"Wrote {scheduled_index} scheduled records")
    print("done")


def main():
    args = parse_args()
    schedule_vectors(args)


if __name__ == "__main__":
    main()