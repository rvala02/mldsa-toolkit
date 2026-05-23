import csv
import subprocess
import os
from pathlib import Path
from collections import Counter

from dilithium_py.ml_dsa.ml_dsa import ML_DSA
from dilithium_py.ml_dsa.default_parameters import DEFAULT_PARAMETERS
from dilithium_py.ml_dsa.pkcs import sk_from_pem, sk_to_pem

# ML-DSA parameter set used for the reconstruction
SCHEME_NAME = "ML_DSA_65" # Options: "ML_DSA_44", "ML_DSA_65", or "ML_DSA_87".
OPENSSL_SCHEME_NAME = "ML-DSA-65" # Options: "ML-DSA-44", "ML-DSA-65", or "ML-DSA-87".

# Number of key pairs for which datasets are generated
N_KEYS = 10 

# Number of messages to be collected for early-rejection pattern per key.
N_EARLY = 0

# Number of clean messages to collect per key.
N_CLEAN = 500000

# Dir where generated keys and messages are stored
KEYS_DIR = Path("test")

DETERMINISTIC = True
MSG_LEN = 32
CTX = b""

# Early rejection filtering mode:
# - "simple": Check total early rejections (z + r0), regardless of which type
# - "detailed": Specify exact counts for z and r0 rejections separately
EARLY_MODE = "detailed"  # Options: "simple" or "detailed"

# For simple mode, specify the exact total number of early rejections:
# Set to None to match any number of early rejections (> 0)
EARLY_TOTAL_COUNT = None  # e.g., 4 for exactly 4 total early rejections (z + r0)

# For detailed mode, specify the required counts:
# Set to None to ignore that type of rejection
# If AUTO_DISCOVER_PATTERN is True, these will be set automatically based on preround
EARLY_Z_COUNT = 0   # e.g., 2 for exactly 2 z rejections
EARLY_R0_COUNT = 0  # e.g., 2 for exactly 2 r0 rejections

# Optimization: Auto-discover the most common rejection pattern
AUTO_DISCOVER_PATTERN = False  # If True, preround will find most common (z, r0) pattern
PREROUND_SAMPLES_PER_KEY = 0  # Number of signatures to test per key in preround

params = DEFAULT_PARAMETERS[SCHEME_NAME]
mldsa = ML_DSA(params)

def is_clean(stats):
    return stats["attempts"] == 1

def is_early(stats):
    """
    Check if stats match the early rejection criteria.
    
    In "simple" mode: returns True if the total early rejections (z + r0) match
                     EARLY_TOTAL_COUNT (or > 0 if EARLY_TOTAL_COUNT is None) and
                     there are no late rejections.
    
    In "detailed" mode: returns True if the z and r0 counts match the specified
                       requirements (EARLY_Z_COUNT and EARLY_R0_COUNT) and
                       there are no late rejections.
    """
    # Must have no late rejections
    if stats["late"] > 0:
        return False
    
    if EARLY_MODE == "simple":
        # Simple mode: check total early rejections (z + r0)
        total_early = stats["z"] + stats["r0"]
        if EARLY_TOTAL_COUNT is None:
            # If not specified, just check if there are any early rejections
            return total_early > 0
        else:
            # Check for exact count
            return total_early == EARLY_TOTAL_COUNT
    
    elif EARLY_MODE == "detailed":
        # Detailed mode: check specific z and r0 counts
        z_match = EARLY_Z_COUNT is None or stats["z"] == EARLY_Z_COUNT
        r0_match = EARLY_R0_COUNT is None or stats["r0"] == EARLY_R0_COUNT
        return z_match and r0_match
    
    else:
        raise ValueError(f"Unknown EARLY_MODE: {EARLY_MODE}. Must be 'simple' or 'detailed'")

# def init_csv_file(path: Path):
#     f = path.open("w", newline="")
#     w = csv.writer(f)
#     w.writerow(["msg_hex"])
#     return f, w

def count_existing_rows(path: Path) -> int:
    if not path.exists() or path.stat().st_size == 0:
        return 0
    with path.open("r", newline="") as f:
        r = csv.reader(f)
        try:
            next(r)
        except StopIteration:
            return 0
        return sum(1 for _ in r)

def open_csv_resume(path: Path, header: list[str]):
    """
    If file exists and is non-empty: append and return existing row count.
    Else: create, write heaser, return 0
    """
    if path.exists() and path.stat().st_size > 0:
        existing = count_existing_rows(path)
        f = path.open("a", newline="")
        w = csv.writer(f)
        return f, w, existing
    else:
        f = path.open("w", newline="")
        w = csv.writer(f)
        w.writerow(header)
        f.flush()
        return f, w, 0

def openssl_gen_keypair(key_dir: Path, scheme_name: str) -> tuple[Path, Path]:
    key_dir.mkdir(parents=True, exist_ok=True)
    sk_pem = key_dir / "sk.pem"
    pk_pem = key_dir / "pk.pem"

    subprocess.run(
        ["openssl", "genpkey", "-algorithm", scheme_name, "-out", str(sk_pem)],
        check=True,
        capture_output=True,
    )
    subprocess.run(
        ["openssl", "pkey", "-in", str(sk_pem), "-pubout", "-out", str(pk_pem)],
        check=True,
        capture_output=True,
    )
    return sk_pem, pk_pem

def sign_one_attempt_trace(
    mldsa: ML_DSA,
    mu: bytes,
    m_prime: bytes,
    s1_hat,
    s2_hat,
    t0_hat,
    A_hat,
    rho_prime: bytes,
    kappa: int,
):
    alpha = mldsa.gamma_2 << 1

    y = mldsa._expand_mask_vector(rho_prime, kappa)
    y_hat = y.to_ntt()
    w = (A_hat @ y_hat).from_ntt()

    kappa += mldsa.l

    w1 = w.high_bits(alpha)
    w1_bytes = w1.bit_pack_w(mldsa.gamma_2)

    c_tilde = mldsa._h(mu + w1_bytes, mldsa.c_tilde_bytes)
    c = mldsa.R.sample_in_ball(c_tilde, mldsa.tau)
    c_hat = c.to_ntt()

    z = y + s1_hat.scale(c_hat).from_ntt()
    r0 = (w - s2_hat.scale(c_hat).from_ntt()).low_bits(alpha)
    
    z_fail = z.check_norm_bound(mldsa.gamma_1 - mldsa.beta)
    r0_fail = r0.check_norm_bound(mldsa.gamma_2 - mldsa.beta)

    if z_fail:
        return "early_z", kappa
    if r0_fail:
        return "early_r0", kappa
    
    c_t0 = t0_hat.scale(c_hat).from_ntt()
    h = (-c_t0).make_hint(w - s2_hat.scale(c_hat).from_ntt() + c_t0, alpha)

    c_t0_fail = c_t0.check_norm_bound(mldsa.gamma_2)
    h_fail = h.sum_hint() > mldsa.omega

    if c_t0_fail or h_fail:
        return "late", kappa

    return "accepted", kappa


def sign_full_run_trace(mldsa: ML_DSA, sk: bytes, m: bytes, ctx: bytes = b""):
    if len(ctx) > 255:
        raise ValueError("ctx too long")

    m_prime = bytes([0]) + bytes([len(ctx)]) + ctx + m

    rho, k, tr, s1, s2, t0 = mldsa._unpack_sk(sk)

    s1_hat = s1.to_ntt()
    s2_hat = s2.to_ntt()
    t0_hat = t0.to_ntt()
    A_hat = mldsa._expand_matrix_from_seed(rho)

    rnd = bytes(32) if DETERMINISTIC else mldsa.random_bytes(32)
    mu = mldsa._h(tr + m_prime, 64)
    rho_prime = mldsa._h(k + rnd + mu, 64)

    kappa = 0

    stats = {
        "attempts": 0,
        "z": 0,
        "r0": 0,
        "late": 0
    }

    while True:
        stats["attempts"] += 1

        reason, kappa = sign_one_attempt_trace(
            mldsa,
            mu,
            m_prime,
            s1_hat,
            s2_hat,
            t0_hat,
            A_hat,
            rho_prime,
            kappa,
        )

        if reason == "accepted":
            break

        # Map rejection reasons to stats keys
        if reason == "early_z":
            stats["z"] += 1
        elif reason == "early_r0":
            stats["r0"] += 1
        elif reason == "late":
            stats["late"] += 1

    return stats

def classify_rejection(rej_z, rej_r0, rej_ct0, rej_h):
    early = rej_z + rej_r0
    late  = rej_ct0 + rej_h

    if early == 0 and late == 0:
        return "none"
    if early > late:
        return "early"
    if late > early:
        return "late"
    return "mixed"  

def preround_discover_pattern():
    print("PREROUND: Discovering most common rejection pattern")
    
    pattern_counter = Counter()
    
    for key_id in range(N_KEYS):
        print(f"\nPreround: Processing key {key_id}/{N_KEYS-1}")
        
        key_dir = KEYS_DIR / f"key_{key_id:03d}"
        key_dir.mkdir(parents=True, exist_ok=True)
        
        sk_pem_path = key_dir / "sk.pem"
        if not sk_pem_path.exists():
            sk_pem_path, pk_pem_path = openssl_gen_keypair(
                key_dir, OPENSSL_SCHEME_NAME
            )
        else:
            pk_pem_path = key_dir / "pk.pem"
        
        _, sk_bytes, _, _ = sk_from_pem(sk_pem_path.read_bytes())
        
        for i in range(PREROUND_SAMPLES_PER_KEY):
            msg = os.urandom(MSG_LEN)
            stats = sign_full_run_trace(mldsa, sk_bytes, msg, ctx=CTX)
            
            if stats["late"] == 0 and (stats["z"] > 0 or stats["r0"] > 0):
                pattern = (stats["z"], stats["r0"])
                pattern_counter[pattern] += 1
            
            if (i + 1) % 200 == 0:
                print(f"  Key {key_id}: {i+1}/{PREROUND_SAMPLES_PER_KEY} signatures tested")
    
    # Find the most common pattern
    if not pattern_counter:
        print("\nWARNING: No early rejection patterns found in preround!")
        print("Falling back to configured EARLY_Z_COUNT and EARLY_R0_COUNT")
        return None
    
    most_common_pattern = pattern_counter.most_common(1)[0]
    z_count, r0_count = most_common_pattern[0]
    pattern_frequency = most_common_pattern[1]
    total_samples = sum(pattern_counter.values())
    
    print("PREROUND RESULTS:")
    print(f"Total early rejection patterns found: {total_samples}")
    print(f"\nTop 5 most common patterns:")
    for pattern, count in pattern_counter.most_common(5):
        z, r0 = pattern
        percentage = (count / total_samples) * 100
        print(f"  (z={z}, r0={r0}): {count} occurrences ({percentage:.2f}%)")
    
    print(f"\nSelected pattern: (z={z_count}, r0={r0_count})")
    print(f"  Frequency: {pattern_frequency}/{total_samples} ({pattern_frequency/total_samples*100:.2f}%)")
    print("=" * 60 + "\n")
    
    return (z_count, r0_count)

def main():
    global EARLY_Z_COUNT, EARLY_R0_COUNT
    
    KEYS_DIR.mkdir(parents=True, exist_ok=True)
    
    # Preround: Discover most common pattern if enabled
    if AUTO_DISCOVER_PATTERN and EARLY_MODE == "detailed":
        discovered_pattern = preround_discover_pattern()
        if discovered_pattern:
            EARLY_Z_COUNT, EARLY_R0_COUNT = discovered_pattern
            print(f"Using discovered pattern: z={EARLY_Z_COUNT}, r0={EARLY_R0_COUNT}\n")
        else:
            print(f"Using configured pattern: z={EARLY_Z_COUNT}, r0={EARLY_R0_COUNT}\n")
    elif AUTO_DISCOVER_PATTERN and EARLY_MODE == "simple":
        print("Note: AUTO_DISCOVER_PATTERN is enabled but EARLY_MODE is 'simple'.")
        print("Auto-discovery only works with 'detailed' mode. Using configured values.\n")
    
    print("DATASET GENERATION")
    print(f"Target pattern: z={EARLY_Z_COUNT}, r0={EARLY_R0_COUNT}\n")

    for key_id in range(N_KEYS):
        print(f"Processing key {key_id}")

        key_dir = KEYS_DIR/f"key_{key_id:03d}"
        key_dir.mkdir(parents=True, exist_ok=True)

        # Reuse key if it exists (from preround), otherwise generate new one
        sk_pem_path = key_dir / "sk.pem"
        if not sk_pem_path.exists():
            sk_pem_path, pk_pem_path = openssl_gen_keypair(
                key_dir, OPENSSL_SCHEME_NAME
            )
        else:
            pk_pem_path = key_dir / "pk.pem"

        _, sk_bytes, _, _ = sk_from_pem(sk_pem_path.read_bytes())

        clean_path = key_dir / "clean.csv"
        early_path = key_dir / "early.csv"
        
        clean_file, clean_writer, clean_count = open_csv_resume(clean_path, ["msg_hex"])
        early_file, early_writer, early_count = open_csv_resume(early_path, ["msg_hex"])

        print(f"Resuming: clean={clean_count}/{N_CLEAN}, early={early_count}/{N_EARLY}")


        trials = 0
        flush_interval = 100  

        try:
            while clean_count < N_CLEAN or early_count < N_EARLY:
                trials += 1
                msg = os.urandom(MSG_LEN)

                stats = sign_full_run_trace(
                    mldsa, sk_bytes, msg, ctx=CTX
                )

                if clean_count < N_CLEAN and is_clean(stats):
                    clean_writer.writerow([msg.hex()])
                    clean_count += 1
                    if clean_count % flush_interval == 0:
                        clean_file.flush()
                    continue

                if early_count < N_EARLY and is_early(stats):
                    early_writer.writerow([msg.hex()])
                    early_count += 1
                    if early_count % flush_interval == 0:
                        early_file.flush()

                if trials % 1000 == 0:
                    print(
                        f" trials={trials}, "
                        f"clean={clean_count}, "
                        f"early={early_count} "
                    )
        finally:
            clean_file.close()
            early_file.close()

        print(
            f"key {key_id}: "
            f"clean={clean_count}, "
            f"early={early_count}, "
            f"trials={trials}"
        )


if __name__ == "__main__":
    main()
