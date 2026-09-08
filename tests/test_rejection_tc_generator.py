import csv
import subprocess
import sys
from pathlib import Path
import pytest

import scripts.rejection_tc_generator as gen

from collections import defaultdict

from dilithium_py.ml_dsa.default_parameters import DEFAULT_PARAMETERS
from dilithium_py.ml_dsa.ml_dsa import ML_DSA

SCRIPT = Path("scripts/rejection_tc_generator.py")
ML_DSA_SCHEMES = ["44", "65", "87"]

def run_generator(out_dir, num_signatures=1000, window_size=5, scheme="44"):
    subprocess.run(
        [
            sys.executable,
            str(SCRIPT),
            "-s",
            scheme,
            "-o",
            str(out_dir),
            "-n",
            str(num_signatures),
            "-w",
            str(window_size),
            "--force",
            "-p",
            str(num_signatures),
        ],
        check=True,
    )


def make_candidate(num_rejections, seed_byte, msg_byte, sig_byte):
    seed = bytes([seed_byte]) * gen.SEED_SIZE
    msg = bytes([msg_byte]) * gen.MSG_SIZE
    sig = bytes([sig_byte]) * 8
    return num_rejections, seed, msg, sig


def read_windows_csv(path):
    with open(path, newline="") as f:
        return list(csv.DictReader(f))


def read_records(path, record_size):
    data = path.read_bytes()
    assert len(data) % record_size == 0
    return [data[i: i + record_size] for i in range(0, len(data), record_size)]


def get_mldsa(scheme="44"):
    return ML_DSA(DEFAULT_PARAMETERS[f"ML_DSA_{scheme}"])


def sign_clean(mldsa, sk, msg):
    return mldsa.sign(sk, msg, ctx=gen.CTX, deterministic=True)


def verify_clean(mldsa, pk, msg, sig):
    return mldsa.verify(pk, msg, sig, ctx=gen.CTX)


def test_write_window_writes_flat_files_and_correct_indexes(tmp_path):
    """
    Verify tahat one written windows produces aligned binary files
    and correct CSV indexes.
    """
    output = gen.WindowOutput(
        path=tmp_path,
        seed_size=gen.SEED_SIZE,
        msg_size=gen.MSG_SIZE,
        sig_size=8,
    )

    records = [
        (bytes([1]) * gen.SEED_SIZE, bytes([2]) * gen.MSG_SIZE, bytes([3]) * 8),
        (bytes([4]) * gen.SEED_SIZE, bytes([5]) * gen.MSG_SIZE, bytes([6]) * 8),
        (bytes([7]) * gen.SEED_SIZE, bytes([8]) * gen.MSG_SIZE, bytes([9]) * 8),
    ]

    output.write_window(num_rejections=2, records=records)
    output.close()

    assert (tmp_path / "keys.bin").stat().st_size == 3 * gen.SEED_SIZE
    assert (tmp_path / "messages.bin").stat().st_size == 3 * gen.MSG_SIZE
    assert (tmp_path / "signatures.bin").stat().st_size == 3 * 8

    rows = read_windows_csv(tmp_path / "windows.csv")
    assert rows == [
        {
            "window_id": "0",
            "start_index": "0",
            "end_index": "2",
            "num_rejections": "2",
            "count": "3",
        }
    ]


def test_multiple_windows_have_continuous_indexes(tmp_path):
    """
    Verify that consecutive windows receive continuous record indexes.
    """
    output = gen.WindowOutput(
        path=tmp_path,
        seed_size=gen.SEED_SIZE,
        msg_size=gen.MSG_SIZE,
        sig_size=8,
    )

    records_a = [
        (bytes([1]) * gen.SEED_SIZE, bytes([2]) * gen.MSG_SIZE, bytes([3]) * 8),
        (bytes([4]) * gen.SEED_SIZE, bytes([5]) * gen.MSG_SIZE, bytes([6]) * 8),
    ]

    records_b = [
        (bytes([7]) * gen.SEED_SIZE, bytes([8]) * gen.MSG_SIZE, bytes([9]) * 8),
        (bytes([10]) * gen.SEED_SIZE, bytes([11]) * gen.MSG_SIZE, bytes([12]) * 8),
    ]

    output.write_window(num_rejections=0, records=records_a)
    output.write_window(num_rejections=3, records=records_b)
    output.close()

    rows = read_windows_csv(tmp_path / "windows.csv")
    assert rows == [
        {
            "window_id": "0",
            "start_index": "0",
            "end_index": "1",
            "num_rejections": "0",
            "count": "2",
        },
        {
            "window_id": "1",
            "start_index": "2",
            "end_index": "3",
            "num_rejections": "3",
            "count": "2",
        },
    ]



def test_buffer_candidate_writes_only_when_bucket_is_full(tmp_path):
    """
    Verify that candidates are written only after their rejection
    bucket reaches the window size.
    """
    output = gen.WindowOutput(
        path=tmp_path,
        seed_size=gen.SEED_SIZE,
        msg_size=gen.MSG_SIZE,
        sig_size=8,
    )

    buckets = defaultdict(list)
    window_size = 3

    assert not gen.buffer_candidate(
        buckets, output, window_size, make_candidate(1, 1, 2, 3)
    )
    assert not gen.buffer_candidate(
        buckets, output, window_size, make_candidate(1, 4, 5, 6)
    )

    assert output.window_id == 0
    assert output.test_cases_written == 0
    assert len(buckets[1]) == 2

    assert gen.buffer_candidate(
        buckets, output, window_size, make_candidate(1, 7, 8, 9)
    )

    assert output.window_id == 1
    assert output.test_cases_written == 3
    assert buckets[1] == []

    output.close()

    rows = read_windows_csv(tmp_path / "windows.csv")
    assert rows[0]["window_id"] == "0"
    assert rows[0]["start_index"] == "0"
    assert rows[0]["end_index"] == "2"
    assert rows[0]["num_rejections"] == "1"
    assert rows[0]["count"] == "3"


def test_only_extended_bucket_is_written(tmp_path):
    """
    Verify that filling one bucket writes only that bucket and leaves
    other buckets unchanged.
    """
    output = gen.WindowOutput(
        path=tmp_path,
        seed_size=gen.SEED_SIZE,
        msg_size=gen.MSG_SIZE,
        sig_size=8,
    )

    buckets = defaultdict(list)
    window_size = 3

    gen.buffer_candidate(buckets, output, window_size, make_candidate(0, 1, 1, 1))
    gen.buffer_candidate(buckets, output, window_size, make_candidate(0, 2, 2, 2))

    gen.buffer_candidate(buckets, output, window_size, make_candidate(1, 3, 3, 3))
    gen.buffer_candidate(buckets, output, window_size, make_candidate(1, 4, 4, 4))

    assert output.window_id == 0
    assert len(buckets[0]) == 2
    assert len(buckets[1]) == 2

    # This fills only bucket 1, so only bucket 1 should be written.
    assert gen.buffer_candidate(
        buckets, output, window_size, make_candidate(1, 5, 5, 5)
    )

    assert output.window_id == 1
    assert len(buckets[0]) == 2
    assert buckets[1] == []

    output.close()

    rows = read_windows_csv(tmp_path / "windows.csv")
    assert rows[0]["num_rejections"] == "1"


def test_rejects_wrong_record_sizes(tmp_path):
    """
    Verify that records with invalid field sizes are rejected before
    writing output.
    """
    output = gen.WindowOutput(
        path=tmp_path,
        seed_size=gen.SEED_SIZE,
        msg_size=gen.MSG_SIZE,
        sig_size=8,
    )

    bad_records = [
        (
            b"x" * (gen.SEED_SIZE - 1),
            b"m" * gen.MSG_SIZE,
            b"s" * 8,
        )
    ]

    with pytest.raises(SystemExit):
        output.write_window(num_rejections=0, records=bad_records)

    output.close()


def test_does_not_overwrite_existing_outputs_without_force(tmp_path):
    """
    Verify that existing output files are not overwritten unless force
    mode is enabled.
    """
    existing = tmp_path / "keys.bin"
    existing.write_bytes(b"already here")

    with pytest.raises(SystemExit):
        gen.WindowOutput(
            path=tmp_path,
            seed_size=gen.SEED_SIZE,
            msg_size=gen.MSG_SIZE,
            sig_size=8,
            force=False,
        )


@pytest.mark.slow
@pytest.mark.parametrize("scheme", ML_DSA_SCHEMES)
def test_e2e_generator_writes_valid_window_layout(tmp_path, scheme):
    """
    Run the generator end-to-end and verify the written window layout
    and file sizes.
    """
    out_dir = tmp_path / "vectors"

    run_generator(out_dir, num_signatures=100, window_size=5, scheme=scheme)

    assert (out_dir / "keys.bin").exists()
    assert (out_dir / "messages.bin").exists()
    assert (out_dir / "signatures.bin").exists()
    assert (out_dir / "windows.csv").exists()

    rows = read_windows_csv(out_dir / "windows.csv")

    assert rows
    assert all(row["count"] == "5" for row in rows)

    for expected_window_id, row in enumerate(rows):
        start_index = int(row["start_index"])
        end_index = int(row["end_index"])
        count = int(row["count"])

        assert int(row["window_id"]) == expected_window_id
        assert start_index == expected_window_id * 5
        assert end_index == start_index + count - 1
        assert int(row["num_rejections"]) >= 0

    mldsa = get_mldsa(scheme)
    sig_size = mldsa._sig_size()
    written_test_cases = len(rows) * 5

    assert (out_dir / "keys.bin").stat().st_size == written_test_cases * gen.SEED_SIZE
    assert (out_dir / "messages.bin").stat().st_size == written_test_cases * gen.MSG_SIZE
    assert (out_dir / "signatures.bin").stat().st_size == written_test_cases * sig_size

    assert written_test_cases <= 100


@pytest.mark.slow
@pytest.mark.parametrize("scheme", ML_DSA_SCHEMES)
def test_e2e_generated_signatures_verify_with_clean_dilithium_py(tmp_path, scheme):
    """
    Verify that generated signatures are valid when checked with a fresh
    ML-DSA instance.
    """
    out_dir = tmp_path / "vectors"

    run_generator(out_dir, num_signatures=100, window_size=5, scheme=scheme)

    mldsa = get_mldsa(scheme)
    sig_size = mldsa._sig_size()

    seeds = read_records(out_dir / "keys.bin", gen.SEED_SIZE)
    messages = read_records(out_dir / "messages.bin", gen.MSG_SIZE)
    signatures = read_records(out_dir / "signatures.bin", sig_size)

    assert len(seeds) == len(messages) == len(signatures)
    assert len(seeds) > 0

    sample_indexes = sorted({0, len(seeds) // 2, len(seeds) - 1})

    for index in sample_indexes:
        pk, _sk = mldsa.key_derive(seeds[index])

        assert verify_clean(
            mldsa,
            pk,
            messages[index],
            signatures[index],
        )


@pytest.mark.slow
@pytest.mark.parametrize("scheme", ML_DSA_SCHEMES)
def test_e2e_generated_signatures_match_clean_deterministic_signing(tmp_path, scheme):
    """
    Verify that stored signatures match deterministic re-signing from the
    stored seed and message.
    """
    out_dir = tmp_path / "vectors"

    run_generator(out_dir, num_signatures=100, window_size=5, scheme=scheme)

    mldsa = get_mldsa(scheme)
    sig_size = mldsa._sig_size()

    seeds = read_records(out_dir / "keys.bin", gen.SEED_SIZE)
    messages = read_records(out_dir / "messages.bin", gen.MSG_SIZE)
    signatures = read_records(out_dir / "signatures.bin", sig_size)

    sample_indexes = sorted({0, len(seeds) // 2, len(seeds) - 1})

    for index in sample_indexes:
        _pk, sk = mldsa.key_derive(seeds[index])
        signature = sign_clean(mldsa, sk, messages[index])

        assert signature == signatures[index]


@pytest.mark.slow
@pytest.mark.parametrize("scheme", ML_DSA_SCHEMES)
def test_e2e_recomputed_rejection_counts_match_windows_csv(tmp_path, scheme):
    """
    Verify that rejection counts recorded in windows.csv match recomputed 
    signing attempts.
    """
    out_dir = tmp_path / "vectors"

    run_generator(out_dir, num_signatures=1000, window_size=5, scheme=scheme)

    rows = read_windows_csv(out_dir / "windows.csv")

    mldsa = get_mldsa(scheme)
    sig_size = mldsa._sig_size()

    seeds = read_records(out_dir / "keys.bin", gen.SEED_SIZE)
    messages = read_records(out_dir / "messages.bin", gen.MSG_SIZE)
    signatures = read_records(out_dir / "signatures.bin", sig_size)

    for row in rows[:10]:
        index = int(row["start_index"])
        expected_rejections = int(row["num_rejections"])

        _pk, sk = mldsa.key_derive(seeds[index])
        key_state = gen.prepare_key_state(mldsa, sk)

        signature, actual_rejections = gen.sign_and_count_rejections(
            mldsa,
            messages[index],
            key_state,
        )

        assert actual_rejections == expected_rejections
        assert signature == signatures[index]