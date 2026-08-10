"""
ML-DSA rejection-count test case generator.

This generates reusable deterministic-signing inputs for timing tests.
Each sorted TC has:
    - 32-byte key seed
    - 32-byte message
    - deterministic signature
    - number of rejection rounds

Output layout:
    out_dir/
        class_00/
            keys.bin
            messages.bin
            signatures.bin
            rejections.bin
        class_01/
            ...
        ...
        class_19/
            ...

For N classes, classes 0..N-2 mean the exact rejection count.
The last class, class_(N-1), is a catch-all >= N-1 rejections.

Example:
    python rejection_tc_generator.py \
        --scheme 44 \
        --classes 20 \
        --target-per-class 10000 \
        --out-dir vectors_mldsa44
"""
import argparse
import gc
import os
import struct
import sys
from multiprocessing import Pool, cpu_count
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
REJECTION_SIZE = 4

WORKER_MLDSA = None
WORKER_CLASSES = None

class ClassOutput:
    def __init__(self, class_id, path, seed_size, msg_size, sig_size, resume):
        self.class_id = class_id
        self.path = path
        self.seed_size = seed_size
        self.msg_size = msg_size
        self.sig_size = sig_size
        self.rejection_size = REJECTION_SIZE

        self.keys_path = path / "keys.bin"
        self.messages_path = path / "messages.bin"
        self.signatures_path = path / "signatures.bin"
        self.rejections_path = path / "rejections.bin"

        path.mkdir(parents=True, exist_ok=True)
        self.count = self._existing_count(resume)

        mode = "ab" if resume else "wb"
        self.keys_fd = open(self.keys_path, mode)
        self.messages_fd = open(self.messages_path, mode)
        self.signatures_fd = open(self.signatures_path, mode)
        self.rejections_fd = open(self.rejections_path, mode)

    def _record_count(self, path, record_size):
        if not path.exists():
            return 0

        size = path.stat().st_size
        if size % record_size != 0:
            error(f"{path} size {size} is not divisible by record size {record_size}")
        return size // record_size

    def _existing_count(self, resume):
        existing = [
            path
            for path in [
                self.keys_path,
                self.messages_path,
                self.signatures_path,
                self.rejections_path,
            ]
            if path.exists() and path.stat().st_size > 0
        ]

        if existing and not resume:
            error(
                f"found existing output files in {self.path}; "
                f"pass --resume to append or delete the directory"
            )

        if not resume:
            return 0

        counts = {
            "keys.bin": self._record_count(self.keys_path, self.seed_size),
            "messages.bin": self._record_count(self.messages_path, self.msg_size),
            "signatures.bin": self._record_count(self.signatures_path, self.sig_size),
            "rejections.bin": self._record_count(
                self.rejections_path,
                self.rejection_size,
            ),
        }

        unique_counts = set(counts.values())
        if len(unique_counts) != 1:
            error(f"inconsistent resume counts in {self.path}: {counts}")

        return unique_counts.pop()

    def is_full(self, target_per_class):
        return self.count >= target_per_class

    def append(self, seed, message, signature, num_rejections):
        if len(seed) != self.seed_size:
            error(f"seed has wrong size: {len(seed)} != {self.seed_size}")
        if len(message) != self.msg_size:
            error(f"message has wrong size: {len(message)} != {self.msg_size}")
        if len(signature) != self.sig_size:
            error(f"signature has wrong size: {len(signature)} != {self.sig_size}")

        self.keys_fd.write(seed)
        self.messages_fd.write(message)
        self.signatures_fd.write(signature)
        self.rejections_fd.write(struct.pack("<I", num_rejections))
        self.count += 1

    def flush(self):
        flush_outputs(
            self.keys_fd,
            self.messages_fd,
            self.signatures_fd,
            self.rejections_fd,
        )

    def close(self):
        self.flush()
        self.keys_fd.close()
        self.messages_fd.close()
        self.signatures_fd.close()
        self.rejections_fd.close()


def parse_args():
    parser = argparse.ArgumentParser(
        description="Generate ML-DSA rejection-count timing vectors."
    )
    parser.add_argument(
        "--scheme", "-s",
        required=True,
        choices=["44", "65", "87"],
        help="ML-DSA scheme: 44, 65 or 87",
    )
    parser.add_argument(
        "--out-dir", "-o",
        required=True,
        type=Path,
        help="Output directory for generated class files.",
    )
    parser.add_argument(
        "--classes", "-c",
        type=int,
        default=20,
        help=(
            "Number of rejection-count classes. Default: 20. "
            "The last class is a catch-all."
        ),
    )
    parser.add_argument(
        "--target-per-class", "-n",
        type=int,
        required=True,
        help="Number of vectors to collect in each class.",
    )
    parser.add_argument(
        "--jobs", "-j",
        type=int,
        default=1,
        help="Number of worker processes. Default: 1.",
    )
    parser.add_argument(
        "--batch-size", "-b",
        type=int,
        default=16,
        help="Number of candidates produced by each worker task. Default: 16.",
    )
    parser.add_argument(
        "--resume", "-r",
        action="store_true",
        help="Resume by appending to existing class files.",
    )
    parser.add_argument(
        "--progress-interval", "-p",
        type=int,
        default=PROGRESS_INTERVAL,
        help=f"Print progress every N generated candidates. Default: {PROGRESS_INTERVAL}.",
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


def class_id_for_rejections(num_rejections, classes):
    return min(num_rejections, classes - 1)


def init_worker(scheme, classes):
    global WORKER_MLDSA, WORKER_CLASSES
    WORKER_MLDSA = ML_DSA(SCHEMES[scheme])
    WORKER_CLASSES = classes


def generate_one_candidate(mldsa, classes):
    seed = os.urandom(SEED_SIZE)
    _pk, sk = mldsa.key_derive(seed)
    msg = os.urandom(MSG_SIZE)

    key_state = prepare_key_state(mldsa, sk)
    signature, num_rejections = sign_and_count_rejections(mldsa, msg, key_state)
    class_id = class_id_for_rejections(num_rejections, classes)

    return class_id, seed, msg, signature, num_rejections


def worker_generate_batch(batch_size):
    return [
        generate_one_candidate(WORKER_MLDSA, WORKER_CLASSES)
        for _ in range(batch_size)
    ]


def make_class_outputs(out_dir, classes, sig_size, target_per_class, resume):
    outputs = []

    for class_id in range(classes):
        class_path = out_dir / f"class_{class_id:02d}"
        output = ClassOutput(
            class_id=class_id,
            path=class_path,
            seed_size=SEED_SIZE,
            msg_size=MSG_SIZE,
            sig_size=sig_size,
            resume=resume,
        )
        if output.count > target_per_class:
            error(
                f"{class_path} already has {output.count} vectors, "
                f"which exceeds target {target_per_class}"
            )
        outputs.append(output)

    return outputs


def all_classes_full(outputs, target_per_class):
    return all(output.is_full(target_per_class) for output in outputs)


def print_progress(outputs, target_per_class, candidates, stored, discarded):
    print(f"candidates={candidates} stored={stored} discarded={discarded}")
    for class_id, output in enumerate(outputs):
        print(f"    class_{class_id:02d}: {output.count}/{target_per_class}")


def close_outputs(outputs):
    for output in outputs:
        output.close()


def store_candidate(outputs, target_per_class, candidate):
    class_id, seed, msg, signature, num_rejections = candidate
    output = outputs[class_id]

    if output.is_full(target_per_class):
        return False

    output.append(seed, msg, signature, num_rejections)
    return True


def process_batch(outputs, target_per_class, batch):
    stored = 0
    discarded = 0

    for candidate in batch:
        if store_candidate(outputs, target_per_class, candidate):
            stored += 1
        else:
            discarded += 1

    return stored, discarded


def generate_vectors_single_process(args, outputs):
    mldsa = ML_DSA(SCHEMES[args.scheme])
    candidates = 0
    stored = sum(output.count for output in outputs)
    discarded = 0

    while not all_classes_full(outputs, args.target_per_class):
        candidate = generate_one_candidate(mldsa, args.classes)
        candidates += 1

        if store_candidate(outputs, args.target_per_class, candidate):
            stored += 1
        else:
            discarded += 1

        if candidates % args.progress_interval == 0:
            for output in outputs:
                output.flush()
            print_progress(
                outputs,
                args.target_per_class,
                candidates,
                stored,
                discarded,
            )
            gc.collect()

    return candidates, stored, discarded


def generate_vectors_parallel(args, outputs):
    candidates = 0
    stored = sum(output.count for output in outputs)
    discarded = 0
    last_reported = 0

    with Pool(
        processes=args.jobs,
        initializer=init_worker,
        initargs=(args.scheme, args.classes),
    ) as pool:
        batch_iter = pool.imap_unordered(
            worker_generate_batch,
            iter(lambda: args.batch_size, None),
            chunksize=1,
        )

        while not all_classes_full(outputs, args.target_per_class):
            batch = next(batch_iter)
            candidates += len(batch)

            batch_stored, batch_discarded = process_batch(
                outputs,
                args.target_per_class,
                batch,
            )
            stored += batch_stored
            discarded += batch_discarded

            if candidates - last_reported >= args.progress_interval:
                for output in outputs:
                    output.flush()
                print_progress(
                    outputs,
                    args.target_per_class,
                    candidates,
                    stored,
                    discarded,
                )
                last_reported = candidates
                gc.collect()

        pool.terminate()
        pool.join()

    return candidates, stored, discarded


def generate_vectors(args):
    if args.classes <= 1:
        error("--classes must be greater than 1")
    if args.target_per_class <= 0:
        error("--target-per-class must be positive")
    if args.jobs <= 0:
        error("--jobs must be positive")
    if args.jobs > cpu_count():
        print(f"WARNING: --jobs {args.jobs} exceeds detected CPU count {cpu_count()}")
    if args.batch_size <= 0:
        error("--batch-size must be positive")
    if args.progress_interval <= 0:
        error("--progress-interval must be positive")

    mldsa = ML_DSA(SCHEMES[args.scheme])
    sig_size = mldsa._sig_size()

    args.out_dir.mkdir(parents=True, exist_ok=True)
    outputs = make_class_outputs(
        args.out_dir,
        args.classes,
        sig_size,
        args.target_per_class,
        args.resume,
    )

    print(f"Scheme: ML-DSA-{args.scheme}")
    print(f"Output: {args.out_dir}")
    print(f"Classes: {args.classes}")
    print(f"Target per class: {args.target_per_class}")
    print(f"Signature size: {sig_size}")
    print(f"Jobs: {args.jobs}")
    print(f"Batch size: {args.batch_size}")
    print(
        f"Class convention: class_00..class_{args.classes - 2:02d} are exact; "
        f"class_{args.classes - 1:02d} is >= {args.classes - 1}"
    )
    print_progress(outputs, args.target_per_class, 0, sum(o.count for o in outputs), 0)

    try:
        if args.jobs == 1:
            candidates, stored, discarded = generate_vectors_single_process(args, outputs)
        else:
            candidates, stored, discarded = generate_vectors_parallel(args, outputs)
    finally:
        close_outputs(outputs)

    print_progress(outputs, args.target_per_class, candidates, stored, discarded)
    print("done")


def main():
    args = parse_args()
    generate_vectors(args)


if __name__ == "__main__":
    main()