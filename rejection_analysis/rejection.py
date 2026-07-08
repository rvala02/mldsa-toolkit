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
import gc
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
        "--resume", "-r",
        action="store_true",
        help="Resume from existing per-key part files in .<out_stem>_parts/",
    )
    parser.add_argument(
        "--out", "-o",
        required=True,
        help="Output CSV file path (coefficients file is derived from this name)",
    )
    return parser.parse_args()

def error(msg):
    print(f"ERROR: {msg}")
    sys.exit(1)

def key_part_paths(out_path, key_id):
    part_dir = out_path.parent / f".{out_path.stem}_parts"
    part_out = part_dir / f"{out_path.stem}.key_{key_id:03d}{out_path.suffix}"
    part_coeff = part_dir / f"{out_path.stem}.key_{key_id:03d}_coefficients{out_path.suffix}"
    return part_dir, part_out, part_coeff

def flush_outputs(*file_handles):
    for handle in file_handles:
        handle.flush()
        os.fsync(handle.fileno())

def count_csv_data_rows(path):
    if not path.exists() or path.stat().st_size == 0:
        return 0

    with open(path, newline="") as in_fd:
        reader = csv.reader(in_fd)
        if next(reader, None) is None:
            return 0
        return sum(1 for _ in reader)

def part_resume_start(part_out, part_coeff, key_id, messages_per_key, resume):
    if not resume or not part_out.exists():
        return 0

    completed_rows = count_csv_data_rows(part_out)
    if completed_rows == 0:
        return 0

    if completed_rows >= messages_per_key:
        return messages_per_key

    with open(part_out, newline="") as in_fd:
        reader = csv.DictReader(in_fd)
        last_row = None
        for last_row in reader:
            pass

    if last_row is None:
        return 0

    if int(last_row["key_id"]) != key_id:
        error(
            f"part file {part_out} ends with key_id {last_row['key_id']}, "
            f"expected {key_id}"
        )

    last_message_id = int(last_row["message_id"])
    if last_message_id != completed_rows - 1:
        error(
            f"part file {part_out} has {completed_rows} rows but last "
            f"message_id is {last_message_id}"
        )

    if not part_coeff.exists():
        error(f"part file {part_out} exists but {part_coeff} is missing")

    if count_csv_data_rows(part_coeff) == 0:
        error(f"part file {part_out} has data but {part_coeff} is empty")

    print(
        f"Resuming key_{key_id:03d} from message {completed_rows} "
        f"({completed_rows}/{messages_per_key} already done)"
    )
    return completed_rows

def expected_message_rows(key_dirs, messages_per_key):
    return len(key_dirs) * messages_per_key

def validate_run_results(results, key_dirs, messages_per_key):
    expected_rows = expected_message_rows(key_dirs, messages_per_key)
    total_rows = sum(result["rows"] for result in results)

    if total_rows != expected_rows:
        error(
            f"incomplete run: expected {expected_rows} message rows "
            f"({len(key_dirs)} keys x {messages_per_key}), got {total_rows}"
        )

    for result in results:
        if result["rows"] != messages_per_key:
            error(
                f"key_{result['key_id']:03d} incomplete: "
                f"{result['rows']}/{messages_per_key} messages"
            )

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

def merge_csv_parts_atomic(part_paths, final_path):
    tmp_path = final_path.with_name(f"{final_path.name}.tmp")
    merge_csv_parts(part_paths, tmp_path)
    tmp_path.replace(final_path)

def cleanup_part_files(results, part_dir):
    for result in results:
        Path(result["part_out"]).unlink(missing_ok=True)
        Path(result["part_coeff"]).unlink(missing_ok=True)

    try:
        part_dir.rmdir()
    except OSError:
        pass

def process_one_key(
    key_id,
    key_dir,
    mldsa,
    scheme,
    messages_path,
    messages_per_key,
    total_messages,
    signing_mode,
    part_out,
    part_coeff,
    resume,
):
    part_out.parent.mkdir(parents=True, exist_ok=True)

    start_message_id = part_resume_start(
        part_out,
        part_coeff,
        key_id,
        messages_per_key,
        resume,
    )

    if start_message_id >= messages_per_key:
        print(f"key_{key_id:03d} already complete, skipping")
        return {
            "key_id": key_id,
            "rows": messages_per_key,
            "coeff_rows": count_csv_data_rows(part_coeff),
            "part_out": str(part_out),
            "part_coeff": str(part_coeff),
        }

    sk = load_sk(key_dir, scheme)
    key_state = prepare_key_state(mldsa, sk)
    del sk

    total_rows = start_message_id
    total_coeff_rows = count_csv_data_rows(part_coeff) if part_coeff.exists() else 0
    last_reported = start_message_id

    block_start = key_id * messages_per_key
    block_end = block_start + messages_per_key - 1

    print(
        f"Processing key_{key_id:03d} "
        f"(messages {block_start}...{block_end})"
    )

    out_mode = "a" if start_message_id > 0 else "w"
    coeff_mode = "a" if start_message_id > 0 else "w"

    with open(messages_path, "rb") as messages_fd, \
        open(part_out, out_mode, newline="") as out_fd, \
        open(part_coeff, coeff_mode, newline="") as coeff_fd:

        writer = csv.writer(out_fd)
        coeff_writer = csv.writer(coeff_fd)

        if out_mode == "w":
            writer.writerow(CSV_HEADER)
            coeff_writer.writerow(COEFF_CSV_HEADER)
            flush_outputs(out_fd, coeff_fd)

        for message_id in range(start_message_id, messages_per_key):
            global_message_id = block_start + message_id
            msg = read_message(messages_fd, global_message_id, total_messages)

            stats = collect_rejection_stats(
                mldsa,
                msg,
                key_state,
                signing_mode,
            )

            del msg

            coeff_count = len(stats["coeff_rows"])

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

            del stats

            total_rows += 1
            total_coeff_rows += coeff_count

            new_reported = report_progress(
                total_rows,
                last_reported,
                f"messages for key_{key_id:03d}",
            )
            if new_reported != last_reported:
                flush_outputs(out_fd, coeff_fd)
                gc.collect()
            last_reported = new_reported

        del key_state
        flush_outputs(out_fd, coeff_fd)

    print(
        f"processed {total_rows}/{messages_per_key} "
        f"messages for key_{key_id:03d}"
    )

    return {
        "key_id": key_id,
        "rows": total_rows,
        "coeff_rows": total_coeff_rows,
        "part_out": str(part_out),
        "part_coeff": str(part_coeff),
    }

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
        resume,
    ) = args_tuple

    out_path = Path(out_path_str)
    _, part_out, part_coeff = key_part_paths(out_path, key_id)
    mldsa = ML_DSA(SCHEMES[scheme])

    return process_one_key(
        key_id,
        Path(key_dir_str),
        mldsa,
        scheme,
        Path(messages_path_str),
        messages_per_key,
        total_messages,
        signing_mode,
        part_out,
        part_coeff,
        resume,
    )

def ensure_clean_part_state(key_dirs, out_path, resume):
    part_dir = out_path.parent / f".{out_path.stem}_parts"
    existing_parts = []

    for key_id, _ in key_dirs:
        _, part_out, _ = key_part_paths(out_path, key_id)
        if part_out.exists() and count_csv_data_rows(part_out) > 0:
            existing_parts.append(part_out)

    if existing_parts and not resume:
        error(
            f"found existing part files in {part_dir}; "
            f"pass --resume to continue or delete that directory"
        )

    return part_dir

def run_all_keys(args, key_dirs, messages_path, out_path, total_messages):
    part_dir = ensure_clean_part_state(key_dirs, out_path, args.resume)
    part_dir.mkdir(parents=True, exist_ok=True)

    if args.resume:
        print(f"Resume enabled; part files in {part_dir}")

    if args.jobs == 1:
        mldsa = ML_DSA(SCHEMES[args.scheme])
        results = []

        for key_id, key_dir in key_dirs:
            _, part_out, part_coeff = key_part_paths(out_path, key_id)
            results.append(
                process_one_key(
                    key_id,
                    key_dir,
                    mldsa,
                    args.scheme,
                    messages_path,
                    args.messages_per_key,
                    total_messages,
                    args.signing_mode,
                    part_out,
                    part_coeff,
                    args.resume,
                )
            )

        return results

    worker_jobs = min(args.jobs, len(key_dirs))
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
            args.resume,
        )
        for key_id, key_dir in key_dirs
    ]

    print(f"Using multiprocessing with {worker_jobs} worker processes")

    with Pool(processes=worker_jobs) as pool:
        return pool.map(process_key_worker, worker_args)

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
    
    total_rows = 0
    total_coeff_rows = 0

    print(f"Loaded {num_keys} keys")
    print(f"Loaded {total_messages} messages")
    print(f"Signing mode: {args.signing_mode}")
    print(f"Jobs: {args.jobs}")
    print(f"Resume: {args.resume}")
    print(f"Output: {out_path}")
    print(f"Coefficient output: {coeff_path}")

    out_path.parent.mkdir(parents=True, exist_ok=True)

    results = run_all_keys(args, key_dirs, messages_path, out_path, total_messages)
    results.sort(key=lambda item: item["key_id"])

    validate_run_results(results, key_dirs, args.messages_per_key)

    part_dir = out_path.parent / f".{out_path.stem}_parts"
    merge_csv_parts_atomic(
        [result["part_out"] for result in results],
        out_path,
    )
    merge_csv_parts_atomic(
        [result["part_coeff"] for result in results],
        coeff_path,
    )

    cleanup_part_files(results, part_dir)

    total_rows = sum(result["rows"] for result in results)
    total_coeff_rows = sum(result["coeff_rows"] for result in results)

    print(
        f"done ({num_keys} keys, {total_rows} message rows, "
        f"{total_coeff_rows} coefficient rows)"
    )

if __name__ == "__main__":
    main()