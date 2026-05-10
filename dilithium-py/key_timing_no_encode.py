"""
Usage:
    python key_timing_no_encode.py -k schedule.bin -d messages.bin -t raw_times.csv -s signatures.bin -m 44|65|87
"""

import argparse
import sys

from dilithium_py.ml_dsa.ml_dsa import ML_DSA
from dilithium_py.ml_dsa.default_parameters import DEFAULT_PARAMETERS

SCHEMES = {
    "44": DEFAULT_PARAMETERS["ML_DSA_44"],
    "65": DEFAULT_PARAMETERS["ML_DSA_65"],
    "87": DEFAULT_PARAMETERS["ML_DSA_87"],
}

SK_SIZES = {
    "44": 2560,
    "65": 4032,
    "87": 4896,
}

MSG_SIZE = 32


def parse_args():
    parser = argparse.ArgumentParser(
        description="ML-DSA timing harness (no_encode)"
    )
    parser.add_argument(
        "--keys", "-k",
        type=str,
        required=True,
        help="Input schedule.bin file",
    )
    parser.add_argument(
        "--messages", "-d",
        type=str,
        required=True,
        help="Input messages.bin file",
    )
    parser.add_argument(
        "--signatures", "-s",
        type=str,
        required=True,
        help="Output file for signatures",
    )
    parser.add_argument(
        "--timings", "-t",
        type=str,
        required=True,
        help="Output file for raw timing data",
    )
    parser.add_argument(
        "--scheme", "-m",
        type=str,
        required=True,
        choices=["44", "65", "87"],
        help="ML-DSA scheme: 44, 65, or 87",
    )

    return parser.parse_args()


def main():
    args = parse_args()

    scheme_name = args.scheme
    sk_size = SK_SIZES[scheme_name]

    scheme = ML_DSA(SCHEMES[scheme_name])

    print(f"Scheme: ML-DSA-{scheme_name}", file=sys.stderr)
    print(f"SK size: {sk_size} bytes", file=sys.stderr)
    print(f"Message size: {MSG_SIZE} bytes", file=sys.stderr)
    print("Timing: scheme._last_time (no_encode)", file=sys.stderr)

    with open(args.keys, "rb") as key_fd, open(args.messages, "rb") as msg_fd, open(
        args.timings, "w"
    ) as time_fd, open(args.signatures, "wb") as sig_fd:

        time_fd.write("raw_times\n")

        count = 0
        while True:
            sk = key_fd.read(sk_size)
            m = msg_fd.read(MSG_SIZE)

            if not sk or not m:
                break

            if len(sk) != sk_size or len(m) != MSG_SIZE:
                print("ERROR: Invalid key or message size", file=sys.stderr)
                sys.exit(1)

            sig = scheme.sign(sk, m, deterministic=True)
            time_diff = scheme._last_time

            time_fd.write(f"{time_diff}\n")
            sig_fd.write(sig)
            count += 1

            if count % 1000 == 0:
                print(f"Processed {count} samples...", file=sys.stderr)

    print(f"done ({count} samples)", file=sys.stderr)


if __name__ == "__main__":
    main()
