"""
Usage:
    python generate_data.py --keys --messages --size 32 --scheme mldsa-44 --count 10000 --output messages.bin
"""

import argparse
import os
import subprocess
from pathlib import Path

BASE = Path(".")
DATA_BIN = BASE / "data.bin"

SCHEMES = {
    "mldsa-44": "ML-DSA-44",
    "mldsa-65": "ML-DSA-65",
    "mldsa-87": "ML-DSA-87"
}

def generate_keys(name: str):
    print(f"Generating keys for {name}")
    outdir = Path(name) / "keys"
    outdir.mkdir(parents=True, exist_ok=True)
    
    pk_path = outdir / "pk.pem"
    sk_path = outdir / "sk.pem"
    
    subprocess.run(
        ["openssl", "genpkey", "-algorithm", SCHEMES[name], "-out", sk_path, "-outform", "PEM"],
        check=True
    )

    subprocess.run(
        ["openssl", "pkey", "-in", sk_path, "-pubout", "-out", pk_path, "-outform", "PEM"],
        check=True
    )

    print("Done.")

def generate_messages(count, output_file, msg_size):
    output_file = Path(output_file)

    print(f"Generating {count} random messages ({msg_size} bytes each.)")

    with open(output_file, "wb") as f:
        for i in range(count):
            f.write(os.urandom(msg_size))
            if (i+1) % 1000 == 0:
                print(f"Generated {i+1}/{count} messages.")

    file_size = output_file.stat().st_size
    print(f"Done. Wrote {file_size} bytes to {output_file}.")

def parse_args():
    parser = argparse.ArgumentParser(
        description="Generate ML-DSA keys and random messages for signing"
    )
    parser.add_argument(
        "--keys", "-k", 
        action="store_true", 
        help="Generate ML-DSA keys"
    )
    parser.add_argument(
        "--messages", "-m", 
        action="store_true", 
        help="Generate random messages"
    )
    parser.add_argument(
        "--size", 
        type=int,
        default=32,
        help="Size of the message"
    )
    parser.add_argument(
        "--scheme", "-s", 
        type=str, 
        default="all", 
        choices=["all", "mldsa-44", "mldsa-65", "mldsa-87"], 
        help="Scheme to generate keys for"
    )
    parser.add_argument(
        "--count", "-c", 
        type=int, 
        default=10000,
        help="Number of messages to generate"
    )
    parser.add_argument(
        "--output", "-o",
        type=str,
        default="messages.bin",
        help="Output file for messages (default: messages.bin)"
    )

    args = parser.parse_args()

    if not args.keys and not args.messages:
        args.keys = True
        args.messages = True
    
    return args

def main():
    args = parse_args()

    if args.keys:
        if args.scheme == "all":
            print("Starting key generation for all schemes")
            for name in SCHEMES:
                generate_keys(name)
        else:
            print(f"Starting key generation for {args.scheme}")
            generate_keys(args.scheme)
    
    if args.messages:
        print(f"Starting message generation")
        generate_messages(args.count, args.output, args.size)
        print("Message generation done")

if __name__ == "__main__":
    main()