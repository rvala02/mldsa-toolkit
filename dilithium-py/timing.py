"""
Usage:
    python timing.py -i messages.bin -o signatures.bin -t timings.csv -s mldsa-44 -k sk.pem --size 32
"""
import argparse
import sys
import time
from pathlib import Path
from dilithium_py.ml_dsa.ml_dsa import ML_DSA
from dilithium_py.ml_dsa.default_parameters import DEFAULT_PARAMETERS
from dilithium_py.ml_dsa.pkcs import sk_from_pem

SCHEMES = {
    "mldsa-44": DEFAULT_PARAMETERS["ML_DSA_44"],
    "mldsa-65": DEFAULT_PARAMETERS["ML_DSA_65"],
    "mldsa-87": DEFAULT_PARAMETERS["ML_DSA_87"]
}

def parse_args():
    parser = argparse.ArgumentParser(
        description="Measure ML-DSA signing times of dilithium-py"
    )
    parser.add_argument(
        "--input", "-i", 
        type=str, 
        required=True,
        help="Input file containing messages to sign"
    )
    parser.add_argument(
        "--output", "-o", 
        type=str, 
        default=None,
        help="File to write signatures to "
        "(default: {scheme}/results/signatures.bin)"
    )
    parser.add_argument(
        "--timings", "-t", 
        type=str, 
        default=None,
        help="File to write timings to "
        "(default: {scheme}/results/timings.csv)"
    ) 
    parser.add_argument(
        "--scheme", "-s", 
        type=str, 
        required=True,
        choices=["mldsa-44", "mldsa-65", "mldsa-87"],
        help="ML-DSA scheme to use"
    )                 
    parser.add_argument(
        "--key", "-k", 
        type=str, 
        default=None,
        help="Path to private key file "
        "(default: {scheme}/keys/sk.pem)"
    )
    parser.add_argument(
        "--size", 
        type=int, 
        default=32,
        help="Size of messages to sign"
    )
    parser.add_argument(
        "--samples", "-n", 
        type=int, 
        default=None,
        help="Number of messages to sign"
    )

    return parser.parse_args()

def load_private_key(key_path: Path):
    file_content = key_path.read_bytes()
    ml_dsa, sk, _, _ = sk_from_pem(file_content)
    return ml_dsa, sk
    

def main():
    args = parse_args()

    scheme_name = args.scheme
    params = SCHEMES[scheme_name]
    input_path = Path(args.input)

    if args.key:
        key_path = Path(args.key)
    else:
        key_path = Path(scheme_name) / "keys" / "sk.pem"
    
    if not key_path.exists():
        print(f"Error: Private key file {key_path} not found")
        sys.exit(1)
    
    result_dir = Path(scheme_name) / "results"
    result_dir.mkdir(parents=True, exist_ok=True)
    
    if args.output:
        output_path = Path(args.output)
    else:
        output_path = result_dir / "signatures.bin"
    
    if args.timings:
        timings_path = Path(args.timings)
    else:
        timings_path = result_dir / "timings.csv"
    
    ml_dsa, sk = load_private_key(key_path)
    scheme = ml_dsa

    block_size = args.size
    samples = args.samples
    if samples is None:
        file_size = input_path.stat().st_size
        samples = file_size // block_size

    print(f"Starting timing measurements for {scheme_name}")
    print(f"Reading messages from {input_path}")
    print(f"Writing signatures to {output_path}")
    print(f"Writing timing data to {timings_path}")
    print(f"Processing {samples} messages of {block_size} bytes each")

    with open(input_path, "rb") as in_fp, \
         open(output_path, "wb") as sig_fp, \
         open(timings_path, "w") as time_fp:
         time_fp.write("raw times\n")


         for i in range(samples):
            data = in_fp.read(block_size)
            if not data or len(data) != block_size:
                break

            time_before = time.monotonic_ns()
            sig = scheme.sign(sk, data, deterministic=True)
            time_after = time.monotonic_ns()

            time_diff = time_after - time_before
            
            time_fp.write("{0}\n".format(time_diff))
            sig_fp.write(sig)

            if (i+1) % 1000 == 0:
                print(f"Processed {i+1}/{samples}")

    print("Done.")

if __name__ == "__main__":
    main()

    