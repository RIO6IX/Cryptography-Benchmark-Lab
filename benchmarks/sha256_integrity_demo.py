"""
SHA-256 correctness, integrity and avalanche demonstration (IE3082 - SHA-256 component).

    python -m benchmarks.sha256_integrity_demo
    python -m benchmarks.sha256_integrity_demo --out results/quick

Steps
  1. Known-answer tests: published SHA-256 vectors (FIPS 180-2 examples /
     RFC 6234), HMAC-SHA-256 vectors (RFC 4231), chunked == one-shot hashing,
     and an independent cross-check against Windows `certutil` when available.
  2. Integrity demonstration on the 1 MB TXT dataset file: the original is
     verified against its reference digest (manifest.csv), then copies with a
     1-bit flip, a 1-byte change and 1 appended byte are verified against the
     same reference. Every modified copy must FAIL; an unmodified copy must PASS.
     The copies are kept in <out>/integrity_demo/ so the digests can be
     re-checked with an OS tool (certutil -hashfile <file> SHA256).
  3. Avalanche experiment: 1,000 single-bit flips at reproducible pseudo-random
     positions of the 1 KB BIN file; the number of digest bits that change is
     recorded. For an ideal 256-bit hash this is Binomial(256, 0.5):
     mean 128, SD 8. Individual flips vary around that; none is expected to be
     exactly 128.

Outputs (in results/ or --out)
  sha256_known_answer_tests.csv
  sha256_integrity_avalanche.csv
  sha256_avalanche_distribution.csv
"""
from __future__ import annotations

import argparse
import csv
import random
import shutil
import ssl
import statistics
import subprocess
import sys
from pathlib import Path

from datasets.generate_test_data import MANIFEST, dataset_path
from src.sha256_hash import (DEFAULT_CHUNK_SIZE, compare_hashes, hamming_distance, hash_bytes,
                             hash_file, hash_file_chunked, hash_file_whole, hash_text,
                             hmac_sha256, integrity_check)

ROOT = Path(__file__).resolve().parent.parent
AVALANCHE_TRIALS = 1000
AVALANCHE_SEED = 3082                  # fixed so the same bit positions are flipped on every run

# (name, message, expected digest). Sources: FIPS 180-2 Appendix B examples,
# repeated in RFC 6234 section 8.5, and the widely published "quick brown fox".
SHA256_VECTORS = [
    ('"" (empty string)', b"",
     "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
    ('"abc" (one block)', b"abc",
     "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"),
    ('"abcdbcde...nopq" (448 bits, two blocks)',
     b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
     "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"),
    ('"abcdefgh...nopqrstu" (896 bits)',
     b"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
     "cf5b16a778af8380036ce59e7b0492370b249b11e8f07a51afac45037afee9d1"),
    ('1,000,000 x "a"', b"a" * 1_000_000,
     "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"),
    ('"The quick brown fox jumps over the lazy dog"', b"The quick brown fox jumps over the lazy dog",
     "d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592"),
]

# RFC 4231 test cases 1 and 2 (HMAC-SHA-256)
HMAC_VECTORS = [
    ("HMAC RFC 4231 case 1", b"\x0b" * 20, b"Hi There",
     "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"),
    ("HMAC RFC 4231 case 2", b"Jefe", b"what do ya want for nothing?",
     "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"),
]


def write_csv(path: Path, header: list, rows: list):
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(header)
        w.writerows(rows)


def manifest_digests() -> dict[str, str]:
    """Reference digests recorded by the dataset generator, keyed by relative path."""
    if not MANIFEST.exists():
        sys.exit(f"{MANIFEST} not found. Run: python -m datasets.generate_test_data")
    with open(MANIFEST, newline="") as f:
        return {r["path"]: r["sha256"] for r in csv.DictReader(f)}


def reference_digest(path: Path) -> str:
    rel = path.relative_to(ROOT).as_posix()
    refs = manifest_digests()
    if rel not in refs or not path.exists():
        sys.exit(f"Missing dataset {rel}. Run: python -m datasets.generate_test_data")
    return refs[rel]


def certutil_sha256(path: Path) -> str | None:
    """Digest from Windows certutil (CryptoAPI), an implementation independent of OpenSSL."""
    if sys.platform != "win32":
        return None
    try:
        out = subprocess.run(["certutil", "-hashfile", str(path), "SHA256"],
                             capture_output=True, text=True, timeout=60).stdout
    except (OSError, subprocess.SubprocessError):
        return None
    for line in out.splitlines():
        cand = line.replace(" ", "").strip().lower()
        if len(cand) == 64 and all(c in "0123456789abcdef" for c in cand):
            return cand
    return None


# --------------------------------------------------------------- 1. known-answer tests
def run_known_answer_tests(out_csv: Path, verbose: bool = True) -> bool:
    rows = []

    def record(name, detail, expected, computed, ok):
        rows.append([name, detail, expected, computed, "PASS" if ok else "FAIL"])

    for name, msg, expected in SHA256_VECTORS:
        got = hash_bytes(msg)
        record(name, f"{len(msg)} bytes", expected, got, got == expected and len(got) == 64)

    got = hash_text("abc")
    record('hash_text("abc") UTF-8', "str input", SHA256_VECTORS[1][2], got, got == SHA256_VECTORS[1][2])

    for name, key, msg, expected in HMAC_VECTORS:
        got = hmac_sha256(key, msg)
        record(name, f"key {len(key)} B, msg {len(msg)} B", expected, got, got == expected)
    plain = hash_bytes(b"Jefe" + b"what do ya want for nothing?")
    record("HMAC differs from SHA-256(key||msg)", "RFC 4231 case 2 inputs",
           "different", plain, plain != HMAC_VECTORS[1][3])

    path = dataset_path("BIN", "1MB")
    ref = reference_digest(path)
    variants = {"4 KiB": hash_file_chunked(path, 4096),
                "64 KiB (default)": hash_file(path),
                "1 MiB": hash_file_chunked(path, 1024**2),
                "odd 1,000 B": hash_file_chunked(path, 1000),
                "whole file": hash_file_whole(path),
                "in-memory hash_bytes": hash_bytes(path.read_bytes())}
    for label, digest in variants.items():
        record(f"1 MB BIN file, {label} read", "must equal manifest digest", ref, digest, digest == ref)

    cu = certutil_sha256(path)
    if cu is not None:
        record("Windows certutil cross-check (1 MB BIN)", "independent implementation", ref, cu, cu == ref)

    write_csv(out_csv, ["test", "detail", "expected", "computed", "result"], rows)
    if verbose:
        for r in rows:
            print(f"  {r[0]:<48} {r[4]}")
    return all(r[4] == "PASS" for r in rows)


# --------------------------------------------------------------- 2. integrity demonstration
def _modified_copy(src: Path, dst: Path, how: str) -> tuple[int | None, str]:
    shutil.copyfile(src, dst)
    if how == "none":
        return None, "unmodified copy"
    if how == "append":
        with open(dst, "ab") as f:
            f.write(b"\n")
        return src.stat().st_size, "1 byte (newline) appended"
    offset = src.stat().st_size // 2
    with open(dst, "r+b") as f:
        f.seek(offset)
        old = f.read(1)[0]
        if how == "bit":
            new = old ^ 0x01                                   # exactly one bit differs
        else:
            new = ord("#") if old != ord("#") else ord("*")    # whole character replaced
        f.seek(offset)
        f.write(bytes([new]))
    change = "lowest bit flipped" if how == "bit" else "character replaced"
    return offset, f"{change}: 0x{old:02x} -> 0x{new:02x} ({chr(old)!r} -> {chr(new)!r})"


def integrity_demo(out: Path) -> tuple[bool, list]:
    src = dataset_path("TXT", "1MB")
    ref = reference_digest(src)
    work = out / "integrity_demo"
    work.mkdir(parents=True, exist_ok=True)

    cases = [("Original 1MB.txt", "original_1MB.txt", "none", "PASS"),
             ("Copy with 1 bit flipped", "modified_1bit_1MB.txt", "bit", "FAIL"),
             ("Copy with 1 byte changed", "modified_1byte_1MB.txt", "byte", "FAIL"),
             ("Copy with 1 byte appended", "modified_append_1MB.txt", "append", "FAIL")]
    rows, all_ok = [], True
    print(f"  Reference digest (manifest.csv): {ref}")
    for name, fname, how, expected in cases:
        dst = work / fname
        offset, change = _modified_copy(src, dst, how)
        res = integrity_check(dst, ref)
        ok = res.status == expected
        all_ok &= ok
        rows.append([name, dst.relative_to(ROOT).as_posix(), dst.stat().st_size,
                     "" if offset is None else offset, change, res.actual, ref,
                     res.differing_bits, res.status, expected, "yes" if ok else "NO"])
        print(f"  {name:<27} {res.actual}  bits changed {res.differing_bits:>3}/256  "
              f"verification {res.status}  (expected {expected})")
    write_csv(out / "sha256_integrity_avalanche.csv",
              ["test", "file", "bytes", "modified_offset", "change", "sha256", "reference_sha256",
               "differing_bits_of_256", "verification", "expected", "as_expected"], rows)
    return all_ok, rows


# --------------------------------------------------------------- 3. avalanche experiment
def avalanche_experiment(out: Path, trials: int = AVALANCHE_TRIALS) -> dict:
    base = dataset_path("BIN", "1KB")
    reference_digest(base)                         # confirms the file exists and is listed
    msg = base.read_bytes()
    h0 = hash_bytes(msg)
    rng = random.Random(AVALANCHE_SEED)            # positions only; not used for anything secret
    rows, dists = [], []
    for t in range(1, trials + 1):
        bit = rng.randrange(len(msg) * 8)
        m = bytearray(msg)
        m[bit // 8] ^= 1 << (bit % 8)
        d = hamming_distance(h0, hash_bytes(bytes(m)))
        dists.append(d)
        rows.append([t, bit, bit // 8, d])
    write_csv(out / "sha256_avalanche_distribution.csv",
              ["trial", "flipped_bit_index", "byte_offset", "differing_bits_of_256"], rows)
    stats = {"trials": trials, "mean": statistics.mean(dists), "sd": statistics.stdev(dists),
             "min": min(dists), "max": max(dists),
             "within_3sd": sum(104 <= d <= 152 for d in dists) / trials * 100}
    print(f"  {trials} single-bit flips of the 1 KB BIN file: mean {stats['mean']:.2f} bits changed "
          f"(SD {stats['sd']:.2f}, min {stats['min']}, max {stats['max']}); ideal mean 128, SD 8")
    print(f"  {stats['within_3sd']:.1f} % of trials within 128 +/- 24 bits (ideal about 99.7 %)")
    return stats


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--out", type=Path, default=ROOT / "results")
    args = ap.parse_args()
    args.out = args.out.resolve()
    args.out.mkdir(parents=True, exist_ok=True)

    print(f"hashlib SHA-256 ({ssl.OPENSSL_VERSION}); default chunk size {DEFAULT_CHUNK_SIZE:,} bytes")
    print(f'Text example: SHA-256("IE3082 Cryptography") = {hash_text("IE3082 Cryptography")}')

    print("\n1. Known-answer tests:")
    kat_ok = run_known_answer_tests(args.out / "sha256_known_answer_tests.csv")
    print("\n2. Integrity demonstration (1 MB TXT file):")
    integ_ok, rows = integrity_demo(args.out)
    a, b = rows[0][5], rows[1][5]
    print(f"  digest A (original) != digest B (1 bit flipped): {not compare_hashes(a, b)}")
    print("\n3. Avalanche experiment:")
    avalanche_experiment(args.out)

    ok = kat_ok and integ_ok
    print(f"\n{'ALL CHECKS PASSED' if ok else 'SOME CHECKS FAILED'} - CSV files written to {args.out}")
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
