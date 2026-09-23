"""
AES-GCM performance benchmark (IE3082 Cryptography - AES component).

    python -m benchmarks.benchmark_aes                 # full run: 3 keys x 6 sizes x 4 types x 10 trials
    python -m benchmarks.benchmark_aes --types BIN     # binary data only
    python -m benchmarks.benchmark_aes --quick         # smoke test, written to results/quick/

Method (per file type and input size)
  1. The input file is read from datasets/data once (file I/O is never timed).
  2. One warm-up encrypt/decrypt per key size is run and discarded.
  3. For each trial, every key size is run, in an order that rotates per trial,
     so slow drift (CPU temperature, turbo, background load) is spread evenly
     over AES-128/192/256 instead of biasing whichever ran last.
  4. For each (trial, key size): a new CSPRNG key -> timed encryption -> timed
     decryption -> byte-for-byte verification -> separate memory runs ->
     separate CPU-utilisation runs -> process RSS.

Outputs (in results/ or --out):
  aes_raw_trials.csv     one row per trial
  aes_summary.csv        mean/min/max/std per configuration
  correctness_tests.csv  functional and tamper tests (see self_test.py)
  environment.txt        hardware/software/settings of this run
"""
from __future__ import annotations

import argparse
import csv
import sys
import time
from pathlib import Path

import psutil

from benchmarks.measure import (MIB, cpu_method, cpu_percent, environment_info,
                                peak_traced_mb, rss_mb, summarise, timed)
from benchmarks.self_test import run_self_tests
from datasets.generate_test_data import FILE_TYPES, SIZES, dataset_path
from src.aes_crypto import VALID_KEY_SIZES, AESGCMCipher, generate_key, verify_decryption

ROOT = Path(__file__).resolve().parent.parent
MIN_TRIALS = 10

RAW_HEADER = ["key_size", "key_bits", "file_type", "input_size", "input_bytes", "input_MB",
              "trial", "enc_time_ms", "dec_time_ms", "enc_throughput_MBps", "dec_throughput_MBps",
              "enc_cpu_pct", "dec_cpu_pct", "enc_cpu_os_pct", "dec_cpu_os_pct", "enc_peak_MB", "dec_peak_MB", "rss_MB", "verified"]

SUMMARY_HEADER = ["key_size", "key_bits", "file_type", "input_size", "input_bytes", "input_MB", "trials",
                  "enc_mean_ms", "enc_min_ms", "enc_max_ms", "enc_std_ms", "enc_cv_pct",
                  "dec_mean_ms", "dec_min_ms", "dec_max_ms", "dec_std_ms", "dec_cv_pct",
                  "enc_throughput_MBps", "dec_throughput_MBps",
                  "enc_cpu_mean_pct", "enc_cpu_std_pct", "dec_cpu_mean_pct", "dec_cpu_std_pct",
                  "enc_cpu_mean_pct_of_all_cores", "enc_cpu_os_mean_pct", "dec_cpu_os_mean_pct",
                  "enc_peak_mean_MB", "dec_peak_mean_MB", "rss_mean_MB", "rss_max_MB",
                  "correctness"]


def run_trial(bits: int, data: bytes, aad: bytes, cpu_window: float) -> dict:
    cipher = AESGCMCipher(generate_key(bits))        # new key per trial, never stored or printed

    payload, enc_s = timed(lambda: cipher.encrypt(data, aad))
    recovered, dec_s = timed(lambda: cipher.decrypt(payload))
    verified = verify_decryption(data, recovered)
    del recovered

    enc_peak = peak_traced_mb(lambda: cipher.encrypt(data, aad))
    dec_peak = peak_traced_mb(lambda: cipher.decrypt(payload))
    enc_cpu, enc_cpu_os = cpu_percent(lambda: cipher.encrypt(data, aad), cpu_window)
    dec_cpu, dec_cpu_os = cpu_percent(lambda: cipher.decrypt(payload), cpu_window)
    return {"enc_s": enc_s, "dec_s": dec_s, "enc_cpu": enc_cpu, "dec_cpu": dec_cpu,
            "enc_cpu_os": enc_cpu_os, "dec_cpu_os": dec_cpu_os,
            "enc_peak": enc_peak, "dec_peak": dec_peak, "rss": rss_mb(), "verified": verified}


def summarise_config(bits, ftype, label, size, trials: list[dict], cores: int) -> list:
    mb = size / MIB
    e = summarise([t["enc_s"] * 1000 for t in trials])
    d = summarise([t["dec_s"] * 1000 for t in trials])
    ec = summarise([t["enc_cpu"] for t in trials])
    dc = summarise([t["dec_cpu"] for t in trials])
    rss = [t["rss"] for t in trials]
    passed = sum(t["verified"] for t in trials)
    return [f"AES-{bits}", bits, ftype, label, size, mb, len(trials),
            e["mean"], e["min"], e["max"], e["std"], e["std"] / e["mean"] * 100,
            d["mean"], d["min"], d["max"], d["std"], d["std"] / d["mean"] * 100,
            mb / (e["mean"] / 1000), mb / (d["mean"] / 1000),
            ec["mean"], ec["std"], dc["mean"], dc["std"], ec["mean"] / cores,
            summarise([t["enc_cpu_os"] for t in trials])["mean"],
            summarise([t["dec_cpu_os"] for t in trials])["mean"],
            summarise([t["enc_peak"] for t in trials])["mean"],
            summarise([t["dec_peak"] for t in trials])["mean"],
            summarise(rss)["mean"], max(rss),
            f"PASS {passed}/{len(trials)}" if passed == len(trials) else f"FAIL {len(trials) - passed}/{len(trials)}"]


def write_csv(path: Path, header: list, rows: list):
    with open(path, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(header)
        for row in rows:
            w.writerow([f"{v:.6g}" if isinstance(v, float) else v for v in row])


def benchmark(key_sizes, types, sizes, trials, warmup, cpu_window, out: Path):
    raw, summary = [], []
    cores = psutil.cpu_count(logical=True)
    failures = 0
    for ftype in types:
        for label in sizes:
            path = dataset_path(ftype, label)
            if not path.exists():
                sys.exit(f"Missing dataset {path}. Run: python -m datasets.generate_test_data")
            data = path.read_bytes()
            size = len(data)
            per_key = {bits: [] for bits in key_sizes}

            for bits in key_sizes:                     # warm-up, discarded
                for _ in range(warmup):
                    c = AESGCMCipher(generate_key(bits))
                    c.decrypt(c.encrypt(data, b"warmup"))

            for trial in range(trials):
                shift = trial % len(key_sizes)
                for bits in key_sizes[shift:] + key_sizes[:shift]:
                    aad = f"AES-{bits}|{ftype}|{label}".encode()
                    t = run_trial(bits, data, aad, cpu_window)
                    per_key[bits].append(t)
                    failures += not t["verified"]
                    mb = size / MIB
                    raw.append([f"AES-{bits}", bits, ftype, label, size, mb, trial + 1,
                                t["enc_s"] * 1000, t["dec_s"] * 1000, mb / t["enc_s"], mb / t["dec_s"],
                                t["enc_cpu"], t["dec_cpu"], t["enc_cpu_os"], t["dec_cpu_os"], t["enc_peak"], t["dec_peak"], t["rss"],
                                "PASS" if t["verified"] else "FAIL"])

            for bits in key_sizes:
                row = summarise_config(bits, ftype, label, size, per_key[bits], cores)
                summary.append(row)
                print(f"  AES-{bits:<3} {ftype:<3} {label:>5}: enc {row[7]:10.4f} ms (sd {row[10]:.4f})  "
                      f"dec {row[12]:10.4f} ms  {row[17]:9.1f} MB/s  CPU {row[19]:5.1f}%  {row[-1]}")
            del data

    write_csv(out / "aes_raw_trials.csv", RAW_HEADER, raw)
    write_csv(out / "aes_summary.csv", SUMMARY_HEADER, summary)
    return failures


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--keys", nargs="+", type=int, default=list(VALID_KEY_SIZES), choices=VALID_KEY_SIZES)
    ap.add_argument("--types", nargs="+", default=list(FILE_TYPES), choices=list(FILE_TYPES))
    ap.add_argument("--sizes", nargs="+", default=list(SIZES), choices=list(SIZES))
    ap.add_argument("--trials", type=int, default=MIN_TRIALS)
    ap.add_argument("--warmup", type=int, default=1)
    ap.add_argument("--cpu-window", type=float, default=0.25, help="seconds per CPU measurement")
    ap.add_argument("--out", type=Path, default=ROOT / "results")
    ap.add_argument("--quick", action="store_true",
                    help="smoke test: 3 trials, BIN, 1KB/1MB, output to results/quick (not for the report)")
    args = ap.parse_args()

    if args.quick:
        args.trials, args.types, args.sizes = 3, ["BIN"], ["1KB", "1MB"]
        args.out = ROOT / "results" / "quick"
    elif args.trials < MIN_TRIALS:
        sys.exit(f"--trials must be at least {MIN_TRIALS} for reportable results (use --quick for a smoke test)")
    args.out.mkdir(parents=True, exist_ok=True)

    env = environment_info()
    env.update({"Key sizes": args.keys, "File types": args.types, "Input sizes": args.sizes,
                "Measured trials per configuration": args.trials,
                "Warm-up runs discarded per key size": args.warmup,
                "CPU sampling window (s)": args.cpu_window,
                "CPU measurement": cpu_method(),
                "Started": time.strftime("%Y-%m-%d %H:%M:%S")})
    print("Environment:")
    for k, v in env.items():
        print(f"  {k}: {v}")

    print("\nCorrectness tests:")
    if not run_self_tests(args.out / "correctness_tests.csv"):
        sys.exit("Correctness tests failed - benchmark aborted.")

    n = len(args.keys) * len(args.types) * len(args.sizes)
    print(f"\nBenchmark: {n} configurations x {args.trials} trials")
    t0 = time.perf_counter()
    failures = benchmark(sorted(args.keys), args.types, args.sizes, args.trials,
                         args.warmup, args.cpu_window, args.out)
    env["Finished"] = time.strftime("%Y-%m-%d %H:%M:%S")
    env["Benchmark duration (s)"] = round(time.perf_counter() - t0, 1)
    env["Decryption verification failures"] = failures
    with open(args.out / "environment.txt", "w", encoding="utf-8") as f:
        f.writelines(f"{k}: {v}\n" for k, v in env.items())

    print(f"\nDone in {env['Benchmark duration (s)']} s. Verification failures: {failures}")
    print(f"Results written to {args.out}")
    sys.exit(1 if failures else 0)


if __name__ == "__main__":
    main()
