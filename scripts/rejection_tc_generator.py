"""
ML-DSA rejection-windows test case generator.

This generates reusable deterministic-signing inputs for timing tests.
Each test case has:
    - 32-byte key seed
    - 32-byte message
    - deterministic signature

The generator groups candidates by the number of rejection rounds. Once one 
rejection-count group reaches --window-size candidates, those candidates are
written as one complete window.

Output layout:
    out_dir/
        keys.bin
        messages.bin
        signatures.bin
        windows.csv

windows.csv maps the stream back to rejection-count windows:
    window_id,start_index,end_index,num_rejections,count

Example:
    python rejection_tc_generator.py \
        --scheme 44 \
        --num-signatures 1000000 \
        --window-size 17 \
        --out-dir vectors_mldsa44
"""

import argparse
import csv
import os
import sys
from collections import defaultdict
from pathlib import Path

from dilithium_py.ml_dsa.default_parameters import DEFAULT_PARAMETERS
from dilithium_py.ml_dsa.ml_dsa import ML_DSA
from dilithium_py.utilities.utils import check_norm_bound


SCHEMES = {
    "44": DEFAULT_PARAMETERS["ML_DSA_44"],
    "65": DEFAULT_PARAMETERS["ML_DSA_65"],
    "87": DEFAULT_PARAMETERS["ML_DSA_87"],
}

MSG_SIZE = 32
SEED_SIZE = 32
CTX = b""
PROGRESS_INTERVAL = 1000


class WindowOutput:
    def __init__(self, path, seed_size, msg_size, sig_size, force=False):
        self.path = path
        self.seed_size = seed_size
        self.msg_size = msg_size
        self.sig_size = sig_size

        self.keys_path = path / "keys.bin"
        self.messages_path = path / "messages.bin"
        self.signatures_path = path / "signatures.bin"
        self.windows_path = path / "windows.csv"

        path.mkdir(parents=True, exist_ok=True)
        self._check_existing_outputs(force)

        self.keys_fd = open(self.keys_path, "wb")
        self.messages_fd = open(self.messages_path, "wb")
        self.signatures_fd = open(self.signatures_path, "wb")
        self.windows_fd = open(self.windows_path, "w", newline="")
        self.windows_writer = csv.writer(self.windows_fd)
        self.windows_writer.writerow(
            ["window_id", "start_index", "end_index", "num_rejections", "count"]
        )

        self.window_id = 0
        self.next_index = 0
        self.test_cases_written = 0

    def _check_existing_outputs(self, force):
        output_files = [
            self.keys_path,
            self.messages_path,
            self.signatures_path,
            self.windows_path,
        ]
        existing = [path for path in output_files if path.exists() and path.stat().st_size > 0]
        if existing and not force:
            files = ", ".join(str(path) for path in existing)
            error(f"found existing output files: {files}; pass --force to overwrite")

    def write_window(self, num_rejections, records):
        if not records:
            return

        start_index = self.next_index

        for seed, message, signature in records:
            if len(seed) != self.seed_size:
                error(f"seed has wrong size: {len(seed)} != {self.seed_size}")
            if len(message) != self.msg_size:
                error(f"message has wrong size: {len(message)} != {self.msg_size}")
            if len(signature) != self.sig_size:
                error(f"signature has wrong size: {len(signature)} != {self.sig_size}")

            self.keys_fd.write(seed)
            self.messages_fd.write(message)
            self.signatures_fd.write(signature)
            self.next_index += 1

        end_index = self.next_index - 1
        count = len(records)

        self.windows_writer.writerow(
            [self.window_id, start_index, end_index, num_rejections, count]
        )

        self.window_id += 1
        self.test_cases_written += count

    def flush(self):
        flush_outputs(
            self.keys_fd,
            self.messages_fd,
            self.signatures_fd,
            self.windows_fd,
        )

    def close(self):
        self.flush()
        self.keys_fd.close()
        self.messages_fd.close()
        self.signatures_fd.close()
        self.windows_fd.close()


def parse_args():
    parser = argparse.ArgumentParser(
        description="Generate ML-DSA rejection-window timing vectors."
    )
    parser.add_argument(
        "--scheme",
        "-s",
        required=True,
        choices=["44", "65", "87"],
        help="ML-DSA scheme: 44, 65, 87",
    )
    parser.add_argument(
        "--out-dir",
        "-o",
        required=True,
        type=Path,
        help="Output directory for generated files.",
    )
    parser.add_argument(
        "--num-signatures",
        "-n",
        type=int,
        required=True,
        help="Number of candidate signatures to generate.",
    )
    parser.add_argument(
        "--window_size",
        "-w",
        type=int,
        default=17,
        help="Number of test cases per rejection-count window. Default: 17",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Overwrite existing output files in the output directory.",
    )
    parser.add_argument(
        "--progress-interval",
        "-p",
        type=int,
        default=PROGRESS_INTERVAL,
        help=f"Print progress every N generated candidates. Default: {PROGRESS_INTERVAL}"
    )
    return parser.parse_args()


def error(msg):
    print(f"ERROR: {msg}")
    sys.exit(1)


def flush_outputs(*file_handles):
    for handle in file_handles:
        handle.flush()
        os.fsync(handle.fileno())


def violates_norm_bound(matrix, bound, q):
    for row in matrix._data:
        for poly in row:
            for coeff in poly.coeffs:
                if check_norm_bound(coeff, bound, q):
                    return True

    return False

def prepare_key_state(mldsa, sk):
    rho, k, tr, s1, s2, t0 = mldsa._unpack_sk(sk)
    return {
        "k": k,
        "tr": tr,
        "s1_hat": s1.to_ntt(),
        "s2_hat": s2.to_ntt(),
        "t0_hat": t0.to_ntt(),
        "A_hat": mldsa._expand_matrix_from_seed(rho),
    }


def sign_one_attempt(mldsa, mu, key_state, rho_prime, kappa):
    alpha = mldsa.gamma_2 << 1
    q = mldsa.M.ring.q

    y = mldsa._expand_mask_vector(rho_prime, kappa)
    y_hat = y.to_ntt()
    w = (key_state["A_hat"] @ y_hat).from_ntt()

    kappa += mldsa.l

    w1 = w.high_bits(alpha)
    w1_bytes = w1.bit_pack_w(mldsa.gamma_2)

    c_tilde = mldsa._h(mu + w1_bytes, mldsa.c_tilde_bytes)
    c = mldsa.R.sample_in_ball(c_tilde, mldsa.tau)
    c_hat = c.to_ntt()

    c_s1 = key_state["s1_hat"].scale(c_hat).from_ntt()
    z = y + c_s1
    if violates_norm_bound(z, mldsa.gamma_1 - mldsa.beta, q):
        return True, kappa, None

    c_s2 = key_state["s2_hat"].scale(c_hat).from_ntt()
    r0 = (w - c_s2).low_bits(alpha)
    if violates_norm_bound(r0, mldsa.gamma_2 - mldsa.beta, q):
        return True, kappa, None

    c_t0 = key_state["t0_hat"].scale(c_hat).from_ntt()
    if violates_norm_bound(c_t0, mldsa.gamma_2, q):
        return True, kappa, None

    h = (-c_t0).make_hint(w - c_s2 + c_t0, alpha)
    if h.sum_hint() > mldsa.omega:
        return True, kappa, None

    signature = mldsa._pack_sig(c_tilde, z, h)
    return False, kappa, signature


def sign_and_count_rejections(mldsa, msg, key_state):
    m_prime = bytes([0]) + bytes([len(CTX)]) + CTX + msg
    rnd = bytes(32)

    mu = mldsa._h(key_state["tr"] + m_prime, 64)
    rho_prime = mldsa._h(key_state["k"] + rnd + mu, 64)

    kappa = 0
    rejections = 0

    while True:
        rejected, kappa, signature = sign_one_attempt(
            mldsa,
            mu,
            key_state,
            rho_prime,
            kappa,
        )

        if not rejected:
            return signature, rejections

        rejections += 1


def generate_one_candidate(mldsa):
    seed = os.urandom(SEED_SIZE)
    _pk, sk = mldsa.key_derive(seed)
    msg = os.urandom(MSG_SIZE)

    key_state = prepare_key_state(mldsa, sk)
    signature, num_rejections = sign_and_count_rejections(mldsa, msg, key_state)

    return num_rejections, seed, msg, signature


def buffer_candidate(buckets, output, window_size, candidate):
    num_rejections, seed, msg, signature = candidate
    bucket = buckets[num_rejections]
    bucket.append((seed, msg, signature))

    if len(bucket) == window_size:
        output.write_window(num_rejections, bucket)
        bucket.clear()
        return True

    return False


def count_buffered_candidates(buckets):
    return sum(len(bucket) for bucket in buckets.values())


def format_non_empty_buckets(buckets):
    non_empty = [(rej, len(bucket)) for rej, bucket in sorted(buckets.items()) if bucket]
    if not non_empty:
        return "none"
    return ", ".join(f"{rej}:{count}" for rej, count in non_empty[:10])


def print_progress(candidates, output, buckets):
    print(
        f"candidates={candidates} "
        f"windows={output.window_id} "
        f"stored={output.test_cases_written} "
        f"buffered={count_buffered_candidates(buckets)} "
        f"buffers={format_non_empty_buckets(buckets)}"
    )


def generate_vectors(args):
    if args.num_signatures <= 0:
        error("--num-signatures must be positive")
    if args.window_size <= 0:
        error("--window-size must be positive")
    if args.progress_interval <= 0:
        error("--progress-interval must be positive")

    mldsa = ML_DSA(SCHEMES[args.scheme])
    sig_size = mldsa._sig_size()
    buckets = defaultdict(list)
    output = WindowOutput(
        path=args.out_dir,
        seed_size=SEED_SIZE,
        msg_size=MSG_SIZE,
        sig_size=sig_size,
        force=args.force,
    )

    print(f"Scheme: ML-DSA-{args.scheme}")
    print(f"Output: {args.out_dir}")
    print(f"Candidate signatures: {args.num_signatures}")
    print(f"Window size: {args.window_size}")
    print(f"Signature size: {sig_size}")
    print("Output files: keys.bin, messages.bin, signatures.bin, windows.csv")

    candidates = 0
    try:
        for _ in range(args.num_signatures):
            candidate = generate_one_candidate(mldsa)
            candidates += 1
            buffer_candidate(buckets, output, args.window_size, candidate)

            if candidates % args.progress_interval == 0:
                output.flush()
                print_progress(candidates, output, buckets)

    finally:
        output.close()

    print_progress(candidates, output, buckets)
    print(f"leftover buffered candidates not written: {count_buffered_candidates(buckets)}")
    print("done")


def main():
    args = parse_args()
    generate_vectors(args)


if __name__ == "__main__":
    main()