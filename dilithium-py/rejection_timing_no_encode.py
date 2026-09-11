"""
Usage:
    python key_timing.py -k schedule.bin -i messages.bin -t raw_times.csv -o signatures.bin -s 44|65|87
"""

import argparse
import sys
import time

from dilithium_py.ml_dsa.ml_dsa import ML_DSA
from dilithium_py.ml_dsa.default_parameters import DEFAULT_PARAMETERS

SCHEMES = {
    "44": DEFAULT_PARAMETERS["ML_DSA_44"],
    "65": DEFAULT_PARAMETERS["ML_DSA_65"],
    "87": DEFAULT_PARAMETERS["ML_DSA_87"],
}

SEED_SIZE = 32
MSG_SIZE = 32


def parse_args():
    parser = argparse.ArgumentParser(
        description="ML-DSA rejection-timing harness (no_encode)"
    )
    parser.add_argument(
        "--keys", "-k",
        type=str,
        required=True,
        help="Input keys.bin file with concatenated 32-byte key seeds"
    )
    parser.add_argument(
        "--messages", "-i",
        type=str,
        required=True,
        help="Input messages.bin file"
    )
    parser.add_argument(
        "--signatures", "-o",
        type=str,
        required=False,
        help="Output file for signatures (optional)"
    )
    parser.add_argument(
        "--expected-signatures", "-e",
        type=str,
        required=False,
        help="Input file with expected deterministic signatures",
    )
    parser.add_argument(
        "--timings", "-t",
        type=str,
        required=True,
        help="Output file for raw timing data"
    )
    parser.add_argument(
        "--scheme", "-s",
        type=str,
        required=True,
        choices=["44", "65", "87"],
        help="ML-DSA scheme: 44, 65, or 87"
    )

    return parser.parse_args()


def main():
    args = parse_args()
    
    scheme_name = args.scheme    
    scheme = ML_DSA(SCHEMES[scheme_name])
    
    print(f"Scheme: ML-DSA-{scheme_name}")
    print(f"Seed size: {SEED_SIZE} bytes")
    print(f"Message size: {MSG_SIZE} bytes")
    
    with open(args.keys, "rb") as key_fd, \
         open(args.messages, "rb") as msg_fd, \
         open(args.timings, "w") as time_fd:

        sig_fd = None
        expected_sig_fd = None

        if args.signatures:
            sig_fd = open(args.signatures, "wb")

        if args.expected_signatures:
            expected_sig_fd = open(args.expected_signatures, "rb")
        
        time_fd.write("raw times\n")
        
        count = 0
        while True:
            seed = key_fd.read(SEED_SIZE)
            m = msg_fd.read(MSG_SIZE)
            
            if not seed and not m:
                break

            if not seed:
                print("ERROR: more messages than key seeds")
                sys.exit(1)

            if not m:
                print("ERROR: more key seeds than messages")
                sys.exit(1)

            if len(seed) != SEED_SIZE:
                print("ERROR: truncated key seed")
                sys.exit(1)

            if len(m) != MSG_SIZE:
                print("ERROR: truncated message")
                sys.exit(1)

            _, sk = scheme.key_derive(seed)
            
            sig = scheme.sign(sk, m, deterministic=True)
            time_diff = scheme._last_time

            if expected_sig_fd is not None:
                expected_sig = expected_sig_fd.read(len(sig))

                if not expected_sig:
                    print("ERROR: expected signature file ended early")
                    sys.exit(1)

                if len(expected_sig) != len(sig):
                    print("ERROR: truncated expected signature")
                    sys.exit(1)

                if sig != expected_sig:
                    print(f"ERROR: signature mismatch at sample {count}")
                    sys.exit(1)
            
            time_fd.write(f"{time_diff}\n")

            if sig_fd is not None:
                sig_fd.write(sig)

            count += 1
            
            if count % 1000 == 0:
                print(f"Processed {count} samples...", file=sys.stderr)
    
    print(f"done ({count} samples)", file=sys.stderr)


if __name__ == '__main__':
    main()
