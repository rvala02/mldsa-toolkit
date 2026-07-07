"""
ML-DSA rejection-sampling harness

Usage:
    python rejection.py \\
        --keys-dir test \\
        --messages mesages.bin \\
        --messages-per-key 1000 \\
        --scheme 65 \\
        --signing-mode deterministic \\
        --out raw_rejections.csv
"""

import argparse
import csv
import re
import sys
import os
from multiprocessing import Pool
from pathlib import Path

from dilithium_py.ml_dsa.default_parameters import DEFAULT_PARAMETERS
from dilithium_py.ml_dsa.ml_dsa import ML_DSA
from dilithium_py.ml_dsa.pkcs import sk_from_pem
from dilithium_py.utilities.utils import check_norm_bound


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
CTX = b""
KEY_DIR_PATTERN = re.compile(r"^key_(\d+)$")

CSV_HEADER = [
    "key_id",
    "message_id",
    "global_message_id",
    "rnd",
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

COEFF_CSV_HEADER = [
    "key_id",
    "message_id",
    "global_message_id",
    "attempt_id",
    "reason",
    "first_bad_coeff",
    "num_bad_coeffs",
]

PROGRESS_INTERVAL = 1000

def coeff_out_path(out_path):
    return out_path.with_name(f"{out_path.stem}_coefficients{out_path.suffix}")

def norm_bound_violation_stats(matrix, bound, q):
    """
    Return the first violating coefficient index and the total number of
    norm-bound violations, or None if there are no violations.
    """
    first_bad = None
    num_bad = 0
    flat_index = 0

    for row in matrix._data:
        for poly in row:
            for coeff in poly.coeffs:
                if check_norm_bound(coeff, bound, q):
                    num_bad += 1
                    if first_bad is None:
                        first_bad = flat_index
                flat_index += 1
    
    if first_bad is None:
        return None
    return first_bad, num_bad

def report_progress(count, last_reported, label):
    while last_reported + PROGRESS_INTERVAL <= count:
        last_reported += PROGRESS_INTERVAL
        print(f"Processed {last_reported} {label}...")
    return last_reported

def report_final_progress(count, last_reported, label):
    if count > last_reported:
        print(f"Processed {count} {label}...")

def parse_args():
    parser = argparse.ArgumentParser(
        description="ML-DSA rejection harness for dilithium-py"
    )
    parser.add_argument(
        "--keys-dir", "-k",
        required=True,
        help="Directory containing key_XXX/sk.pem folders",
    )
    parser.add_argument(
        "--messages", "-m",
        required=True,
        help="Message file (32-byte concatenated messages)"
    )
    parser.add_argument(
        "--messages-per-key", "-n",
        type=int, 
        required=True,
        help="Number of messages assigned to each key"
    )
    parser.add_argument(
        "--scheme", "-s",
        required=True,
        choices=["44", "65", "87"],
        help="ML-DSA scheme: 44, 65, or 87"
    )
    parser.add_argument(
        "--signing-mode", "-sm",
        choices=["deterministic", "hedged"],
        default="deterministic",
        help="Signing mode: deterministic or hedged"
    )
    parser.add_argument(
        "--jobs", "-j",
        type=int,
        default=1,
        help="Number of worker processes. Default: 1"
    )
    parser.add_argument(
        "--out", "-o",
        required=True,
        help="Output folder",
    )
    return parser.parse_args()

def error(msg):
    print(f"ERROR: {msg}")
    sys.exit(1)

def key_part_paths(out_path, key_id):
    part_dir = out_path.parent / f".{out_path.stem}_parts"
    part_out = part_dir / f"{out_path.stem}.key_{key_id:03d}{out_path.suffix}"
    part_coeff = part_dir / f"{out_path.stem}.key_{key_id:03d}_coefficients{out_path.suffix}"
    return part_out, part_coeff

def process_key_worker(args_tuple):
    (
        key_id,
        key_dir_str,
        scheme,
        messages_path_str,
        messages_per_key,
        total_messages,
        signing_mode,
        out_path_str,
    ) = args_tuple

    key_dir = Path(key_dir_str)
    messages_path = Path(messages_path_str)
    out_path = Path(out_path_str)

    part_out, part_coeff = key_part_paths(out_path, key_id)

    mldsa = ML_DSA(SCHEMES[scheme])

    sk = load_sk(key_dir, scheme)
    key_state = prepare_key_state(mldsa, sk)
    del sk

    total_rows = 0
    total_coeff_rows = 0

    block_start = key_id * messages_per_key
    block_end = block_start + messages_per_key - 1

    print(
        f"Processing key_{key_id:03d} "
        f"(messages {block_start}...{block_end})"
    )

    with open(messages_path, "rb") as messages_fd, \
        open(part_out, "w", newline="") as out_fd, \
        open(part_coeff, "w", newline="") as coeff_fd:

        writer = csv.writer(out_fd)
        coeff_writer = csv.writer(coeff_fd)

        writer.writerow(CSV_HEADER)
        coeff_writer.writerow(COEFF_CSV_HEADER)

        for message_id in range(messages_per_key):
            global_message_id = block_start + message_id
            msg = read_message(messages_fd, global_message_id, total_messages)

            stats = collect_rejection_stats(
                mldsa,
                msg,
                key_state,
                signing_mode,
            )

            del msg

            write_results_row(
                writer,
                key_id,
                message_id,
                global_message_id,
                stats,
            )

            write_coeff_rows(
                coeff_writer,
                key_id,
                message_id,
                global_message_id,
                stats["coeff_rows"],
            )

            total_rows += 1
            total_coeff_rows += len(stats["coeff_rows"])

        out_fd.flush()
        coeff_fd.flush()
    
    print(
        f"processed {messages_per_key}/{messages_per_key} "
        f"messages for key_{key_id:03d}"
    )

    return {
        "key_id": key_id,
        "rows": total_rows,
        "coeff_rows": total_coeff_rows,
        "part_out": str(part_out),
        "part_coeff": str(part_coeff),
    }

def merge_csv_parts(part_paths, final_path):
    with open(final_path, "w", newline="") as final_fd:
        writer = csv.writer(final_fd)
        wrote_header = False

        for part_path in part_paths:
            with open(part_path, "r", newline="") as part_fd:
                reader = csv.reader(part_fd)
                header = next(reader)

                if not wrote_header:
                    writer.writerow(header)
                    wrote_header = True
                
                for row in reader:
                    writer.writerow(row)

def discover_key_dirs(keys_dir):
    if not keys_dir.exists():
        error(f"keys directory does not exist: {keys_dir}")
    
    key_dirs: list[tuple[int, Path]] = []
    for entry in keys_dir.iterdir():
        if not entry.is_dir():
            continue
        match = KEY_DIR_PATTERN.match(entry.name)
        if not match:
            continue
        key_dirs.append((int(match.group(1)), entry))
    
    if not key_dirs:
        error(f"no key_XXX directories found in {keys_dir}")
    
    key_dirs.sort(key=lambda item: item[0])
    return key_dirs

def load_sk(key_dir, scheme):
    sk_file = key_dir / "sk.pem"
    if not sk_file.exists():
        error(f"sk.pem missing in {key_dir}")
    
    _, sk_bytes, _, _ = sk_from_pem(sk_file.read_bytes())
    expected = SK_SIZES[scheme]
    if len(sk_bytes) != expected:
        error(f"wrong SK size in {key_dir}: {len(sk_bytes)} != {expected}")
    return sk_bytes

def count_messages(messages_path):
    if not messages_path.exists():
        error(f"message file does not exist: {messages_path}")
    
    size = messages_path.stat().st_size
    if size % MSG_SIZE != 0:
        error(f"message file size {size} is not divisible by {MSG_SIZE}")
    return size // MSG_SIZE

def read_message(messages_fd, global_message_id, total_messages):
    if global_message_id >= total_messages:
        error(
            f"not enough messages: need index {global_message_id}, "
            f"but only {total_messages} messages available"
        )
    
    messages_fd.seek(global_message_id * MSG_SIZE)
    msg = messages_fd.read(MSG_SIZE)
    if len(msg) != MSG_SIZE:
        error(f"unexpected end of message file at index {global_message_id}")
    return msg

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

def sign_one_attempt(
    mldsa: ML_DSA,
    mu: bytes,
    s1_hat,
    s2_hat,
    t0_hat,
    A_hat,
    rho_prime: bytes,
    kappa: int
):
    """
    Execute one internal ML-DSA signing attempt.

    The function samples one candidate masking vector, computes intermediate values, 
    and checks the ML-DSA rejection conditions for z, r0, ct0, and the hint weight.

    Returns the rejection reason, the updated kappa value, and coefficient-level
    rejection information.
    """
    alpha = mldsa.gamma_2 << 1
    q = mldsa.M.ring.q

    y = mldsa._expand_mask_vector(rho_prime, kappa)
    y_hat = y.to_ntt()
    w = (A_hat @ y_hat).from_ntt()

    kappa += mldsa.l

    w1 = w.high_bits(alpha)
    w1_bytes = w1.bit_pack_w(mldsa.gamma_2)

    c_tilde = mldsa._h(mu + w1_bytes, mldsa.c_tilde_bytes)
    c = mldsa.R.sample_in_ball(c_tilde, mldsa.tau)
    c_hat = c.to_ntt()

    c_s1 = s1_hat.scale(c_hat).from_ntt()
    z = y + c_s1
    z_stats = norm_bound_violation_stats(z, mldsa.gamma_1 - mldsa.beta, q)
    if z_stats is not None:
        first_bad, num_bad = z_stats
        return "z", kappa, {
            "reason": "z",
            "first_bad_coeff": first_bad,
            "num_bad_coeffs": num_bad,
        }
    
    c_s2 = s2_hat.scale(c_hat).from_ntt()
    r0 = (w - c_s2).low_bits(alpha)
    r0_stats = norm_bound_violation_stats(r0, mldsa.gamma_2 - mldsa.beta, q)
    if r0_stats is not None:
        first_bad, num_bad = r0_stats
        return "r0", kappa, {
            "reason": "r0",
            "first_bad_coeff": first_bad,
            "num_bad_coeffs": num_bad,
        }
    
    c_t0 = t0_hat.scale(c_hat).from_ntt()
    ct0_stats = norm_bound_violation_stats(c_t0, mldsa.gamma_2, q)
    if ct0_stats is not None:
        first_bad, num_bad = ct0_stats
        return "ct0", kappa, {
            "reason": "ct0",
            "first_bad_coeff": first_bad,
            "num_bad_coeffs": num_bad,
        }

    h = (-c_t0).make_hint(w - c_s2 + c_t0, alpha)
    hint_count = h.sum_hint()
    if hint_count > mldsa.omega:
        return "hint", kappa, {
            "reason": "hint",
            "first_bad_coeff": -1,
            "num_bad_coeffs": hint_count
        }
    
    return "accepted", kappa, None

def collect_rejection_stats(mldsa, msg, key_state, signing_mode: str):
    m_prime = bytes([0]) + bytes([len(CTX)]) + CTX + msg

    if signing_mode == "deterministic":
        rnd = bytes([0]*32)
    elif signing_mode == "hedged":
        rnd = os.urandom(32)
    else:
        error(f"unsupported signing mode: {signing_mode}")

    mu = mldsa._h(key_state["tr"] + m_prime, 64)
    rho_prime = mldsa._h(key_state["k"] + rnd + mu, 64)

    kappa = 0
    attempts = 0
    z_rejections = 0
    r0_rejections = 0
    ct0_rejections = 0
    hint_rejections = 0
    first_rejection_reason = "none"
    coeffs_rows = []
    rejection_id = 0

    while True:
        attempts += 1

        reason, kappa, coeff_info = sign_one_attempt(
            mldsa,
            mu,
            key_state["s1_hat"],
            key_state["s2_hat"],
            key_state["t0_hat"],
            key_state["A_hat"],
            rho_prime,
            kappa,
        )

        if reason == "accepted":
            break

        if first_rejection_reason == "none":
            first_rejection_reason = reason
        
        if reason == "z":
            z_rejections += 1
        elif reason == "r0":
            r0_rejections += 1
        elif reason == "ct0":
            ct0_rejections += 1
        elif reason == "hint":
            hint_rejections += 1
        
        coeffs_rows.append({
            "attempt_id": rejection_id,
            **coeff_info,
        })
        rejection_id += 1
    
    total_rejections = attempts - 1
    sum_first_bad_coeff = sum(
        row["first_bad_coeff"]
        for row in coeffs_rows
        if row["first_bad_coeff"] >= 0
    )

    return {
        "rnd": rnd.hex(),
        "attempts": attempts,
        "z_rejections": z_rejections,
        "r0_rejections": r0_rejections,
        "ct0_rejections": ct0_rejections,
        "hint_rejections": hint_rejections,
        "total_rejections": total_rejections,
        "sum_first_bad_coeff": sum_first_bad_coeff,
        "first_rejection_reason": first_rejection_reason,
        "accepted": 1,
        "coeff_rows": coeffs_rows,
    }

def write_results_row(writer, key_id, message_id, global_message_id, stats):
    writer.writerow([
        key_id,
        message_id,
        global_message_id,
        stats["rnd"],
        stats["attempts"],
        stats["z_rejections"],
        stats["r0_rejections"],
        stats["ct0_rejections"],
        stats["hint_rejections"],
        stats["total_rejections"],
        stats["sum_first_bad_coeff"],
        stats["first_rejection_reason"],
        stats["accepted"],
    ])

def write_coeff_rows(writer, key_id, message_id, global_message_id, coeff_rows):
    for row in coeff_rows:
        writer.writerow([
            key_id,
            message_id,
            global_message_id,
            row["attempt_id"],
            row["reason"],
            row["first_bad_coeff"],
            row["num_bad_coeffs"],
        ])

def main():
    args = parse_args()

    if args.messages_per_key <= 0:
        error("--messages-per-key must be positive")
    
    if args.jobs <= 0:
        error("--jobs must be positive")
    
    keys_dir = Path(args.keys_dir)
    messages_path = Path(args.messages)
    out_path = Path(args.out)
    coeff_path = coeff_out_path(out_path)

    key_dirs = discover_key_dirs(keys_dir)

    num_keys = len(key_dirs)
    max_key_id = max(key_id for key_id, _ in key_dirs)
    required_messages = (max_key_id + 1) * args.messages_per_key
    total_messages = count_messages(messages_path)

    if total_messages < required_messages:
        error(
            f"not enough messages: need at least {required_messages} "
            f"for key IDs 0..{max_key_id} with "
            f"{args.messages_per_key} messages per key, "
            f"got {total_messages}"
        )
    
    mldsa = ML_DSA(SCHEMES[args.scheme])
    total_rows = 0
    total_coeff_rows = 0
    last_reported = 0

    print(f"Loaded {num_keys} keys")
    print(f"Loaded {total_messages} messages")
    print(f"Signing mode: {args.signing_mode}")
    print(f"Jobs: {args.jobs}")
    print(f"Output: {out_path}")
    print(f"Coefficient output: {coeff_path}")

    if args.jobs == 1:
        total_rows = 0
        total_coeff_rows = 0
        last_reported = 0

        with open(messages_path, "rb") as messages_fd, \
            open(out_path, "w", newline="") as out_fd, \
            open(coeff_path, "w", newline="") as coeff_fd:

            writer = csv.writer(out_fd)
            coeff_writer = csv.writer(coeff_fd)
            writer.writerow(CSV_HEADER)
            coeff_writer.writerow(COEFF_CSV_HEADER)
            out_fd.flush()
            coeff_fd.flush()

            for key_id, key_dir in key_dirs:
                sk = load_sk(key_dir, args.scheme)
                key_state = prepare_key_state(mldsa, sk)
                del sk

                block_start = key_id * args.messages_per_key
                block_end = block_start + args.messages_per_key - 1

                print(
                    f"Processing key_{key_id:03d} "
                    f"(messages {block_start}...{block_end})"
                )

                for message_id in range(args.messages_per_key):
                    global_message_id = block_start + message_id
                    msg = read_message(messages_fd, global_message_id, total_messages)

                    stats = collect_rejection_stats(
                        mldsa,
                        msg,
                        key_state,
                        args.signing_mode,
                    )

                    del msg

                    write_results_row(
                        writer,
                        key_id,
                        message_id,
                        global_message_id,
                        stats,
                    )

                    write_coeff_rows(
                        coeff_writer,
                        key_id,
                        message_id,
                        global_message_id,
                        stats["coeff_rows"],
                    )

                    total_rows += 1
                    total_coeff_rows += len(stats["coeff_rows"])

                    new_reported = report_progress(
                        total_rows,
                        last_reported,
                        "messages",
                    )
                    if new_reported != last_reported:
                        out_fd.flush()
                        coeff_fd.flush()
                    last_reported = new_reported

                del key_state
                out_fd.flush()
                coeff_fd.flush()

                print(
                    f"processed {args.messages_per_key}/{args.messages_per_key} "
                    f"messages for key_{key_id:03d}"
                )

            report_final_progress(total_rows, last_reported, "messages")
            out_fd.flush()
            coeff_fd.flush()

    else:
        part_dir = out_path.parent / f".{out_path.stem}_parts"
        part_dir.mkdir(parents=True, exist_ok=True)

        worker_jobs = min(args.jobs, num_keys)

        worker_args = [
            (
                key_id,
                str(key_dir),
                args.scheme,
                str(messages_path),
                args.messages_per_key,
                total_messages,
                args.signing_mode,
                str(out_path),
            )
            for key_id, key_dir in key_dirs
        ]

        print(f"Using multiprocessing with {worker_jobs} worker processes")

        with Pool(processes=worker_jobs) as pool:
            results = pool.map(process_key_worker, worker_args)

        results.sort(key=lambda item: item["key_id"])

        total_rows = sum(result["rows"] for result in results)
        total_coeff_rows = sum(result["coeff_rows"] for result in results)

        merge_csv_parts(
            [result["part_out"] for result in results],
            out_path,
        )

        merge_csv_parts(
            [result["part_coeff"] for result in results],
            coeff_path,
        )

        for result in results:
            Path(result["part_out"]).unlink()
            Path(result["part_coeff"]).unlink()

        try:
            part_dir.rmdir()
        except OSError:
            pass

    print(
        f"done ({num_keys} keys, {total_rows} message rows, "
        f"{total_coeff_rows} coefficient rows)"
    )

if __name__ == "__main__":
    main()