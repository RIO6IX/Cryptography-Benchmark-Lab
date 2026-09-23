"""
SHA-256 performance benchmark (IE3082 Cryptography - SHA-256 component).

    python -m benchmarks.benchmark_sha256                 # full run: 4 types x 6 sizes x 10 trials
    python -m benchmarks.benchmark_sha256 --types BIN     # binary data only
    python -m benchmarks.benchmark_sha256 --quick         # smoke test, written to results/quick/

Method (per file type and input size)
  1. Reference digest = the SHA-256 recorded in datasets/manifest.csv when the
     file was generated; the file's size must equal the requested size.
  2. One warm-up hash_file() call is discarded (loads code, brings the file into
     the OS file cache, lets the CPU clock ramp up).
  3. For each of >= 10 trials:
       - file hashing time: time.perf_counter() around hash_file() (64 KiB
         reads). This includes open() and reading from the OS cache.
       - in-memory hashing time: the same bytes, already in RAM, through
         hash_bytes(). The difference between the two is the file I/O cost.
       - separate CPU run: hash_file() repeated for >= --cpu-window seconds
       - separate memory run: tracemalloc peak during one hash_file() call
       - process RSS, and the digest compared with the reference digest
     Time, CPU and memory are measured in separate calls so that the overhead of
     one measurement does not distort another.
  4. Chunk-size experiment on the largest BIN file: 4 KiB, 64 KiB, 1 MiB and
     whole-file reads. The order rotates per trial so drift affects all equally.

Outputs (in results/ or --out)
  sha256_results.csv                one row per trial
  sha256_summary.csv                mean/min/max/SD/CV per configuration
  sha256_chunk_size_experiment.csv  chunk-size comparison
  sha256_known_answer_tests.csv     correctness checks run before benchmarking
  sha256_environment.txt            hardware/software/settings of this run
"""
from __future__ import annotations

import argparse
import csv
import ssl
import sys
import time
from pathlib import Path

import psutil

from benchmarks.measure import (MIB, cpu_method, cpu_percent, environment_info,
                                peak_traced_mb, rss_mb, summarise, timed)
from benchmarks.sha256_integrity_demo import reference_digest, run_known_answer_tests
from datasets.generate_test_data import FILE_TYPES, SIZES, dataset_path
from src.sha256_hash import (DEFAULT_CHUNK_SIZE, compare_hashes, hash_bytes, hash_file,
                             hash_file_chunked, hash_file_whole)

ROOT = Path(__file__).resolve().parent.parent
MIN_TRIALS = 10
CHUNK_SIZES = [4 * 1024, 64 * 1024, 1024**2, None]          # None = whole file in one read

RAW_HEADER = ["dataset_id", "filename", "file_type", "input_size", "input_bytes", "input_MB",
              "trial", "chunk_size_bytes", "hash_time_ms", "inmemory_time_ms",
              "throughput_MBps", "inmemory_throughput_MBps", "cpu_pct", "cpu_os_pct",
              "peak_traced_MB", "rss_MB", "sha256", "verified"]

SUMMARY_HEADER = ["dataset_id", "file_type", "input_size", "input_bytes", "input_MB", "trials",
                  "mean_ms", "min_ms", "max_ms", "std_ms", "cv_pct",
                  "inmemory_mean_ms", "inmemory_min_ms", "inmemory_max_ms", "inmemory_std_ms",
                  "throughput_MBps", "inmemory_throughput_MBps", "io_share_pct",
                  "cpu_mean_pct", "cpu_min_pct", "cpu_max_pct", "cpu_std_pct",
                  "cpu_mean_pct_of_all_cores", "cpu_os_mean_pct",
                  "peak_mean_MB", "peak_min_MB", "peak_max_MB", "peak_std_MB",
                  "rss_mean_MB", "rss_max_MB", "sha256", "digest_consistency"]

CHUNK_HEADER = ["dataset_id", "input_bytes", "read_size", "read_size_bytes", "trials",
                "mean_ms", "min_ms", "max_ms", "std_ms", "cv_pct", "throughput_MBps",
                "peak_traced_MB", "digest_consistency"]


def write_csv(path: Path, header: list, rows: list):
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(header)
        for row in rows:
            w.writerow([f"{v:.6g}" if isinstance(v, float) else v for v in row])


def load_dataset(ftype: str, label: str) -> tuple[Path, str]:
    path = dataset_path(ftype, label)
    ref = reference_digest(path)                      # exits with a hint if missing
    if path.stat().st_size != SIZES[label]:
        sys.exit(f"{path} is {path.stat().st_size} bytes, expected {SIZES[label]}. Regenerate the datasets.")
    return path, ref


def run_trial(path: Path, data: bytes, cpu_window: float) -> dict:
    digest, t_file = timed(lambda: hash_file(path))
    mem_digest, t_mem = timed(lambda: hash_bytes(data))
    cpu, cpu_os = cpu_percent(lambda: hash_file(path), cpu_window)
    peak = peak_traced_mb(lambda: hash_file(path))
    return {"digest": digest, "mem_digest": mem_digest, "t_file": t_file, "t_mem": t_mem,
            "cpu": cpu, "cpu_os": cpu_os, "peak": peak, "rss": rss_mb()}


def summarise_config(ftype, label, size, trials: list[dict], ref: str, cores: int) -> list:
    mb = size / MIB
    t = summarise([x["t_file"] * 1000 for x in trials])
    m = summarise([x["t_mem"] * 1000 for x in trials])
    c = summarise([x["cpu"] for x in trials])
    p = summarise([x["peak"] for x in trials])
    rss = [x["rss"] for x in trials]
    ok = sum(x["verified"] for x in trials)
    return [f"{ftype}_{label}", ftype, label, size, mb, len(trials),
            t["mean"], t["min"], t["max"], t["std"], t["std"] / t["mean"] * 100,
            m["mean"], m["min"], m["max"], m["std"],
            mb / (t["mean"] / 1000), mb / (m["mean"] / 1000),
            max(0.0, (t["mean"] - m["mean"]) / t["mean"] * 100),
            c["mean"], c["min"], c["max"], c["std"], c["mean"] / cores,
            summarise([x["cpu_os"] for x in trials])["mean"],
            p["mean"], p["min"], p["max"], p["std"],
            summarise(rss)["mean"], max(rss), ref,
            f"PASS {ok}/{len(trials)}" if ok == len(trials) else f"FAIL {len(trials) - ok}/{len(trials)}"]


def benchmark(types, sizes, trials, warmup, cpu_window, out: Path) -> int:
    raw, summary = [], []
    cores = psutil.cpu_count(logical=True)
    failures = 0
    for ftype in types:
        for label in sizes:
            path, ref = load_dataset(ftype, label)
            data = path.read_bytes()                  # for in-memory timing only; not timed
            size = len(data)
            for _ in range(warmup):
                hash_file(path)
                hash_bytes(data)
            per = []
            for trial in range(1, trials + 1):
                t = run_trial(path, data, cpu_window)
                # verified = file digest matches the reference AND in-memory digest agrees
                t["verified"] = compare_hashes(t["digest"], ref) and compare_hashes(t["mem_digest"], ref)
                failures += not t["verified"]
                per.append(t)
                mb = size / MIB
                raw.append([f"{ftype}_{label}", path.name, ftype, label, size, mb, trial, DEFAULT_CHUNK_SIZE,
                            t["t_file"] * 1000, t["t_mem"] * 1000, mb / t["t_file"], mb / t["t_mem"],
                            t["cpu"], t["cpu_os"], t["peak"], t["rss"], t["digest"],
                            "PASS" if t["verified"] else "FAIL"])
            row = summarise_config(ftype, label, size, per, ref, cores)
            summary.append(row)
            print(f"  {ftype:<3} {label:>5}: file {row[6]:9.4f} ms (sd {row[9]:.4f})  "
                  f"in-memory {row[11]:9.4f} ms  {row[15]:8.1f} MB/s  CPU {row[18]:5.1f}%  "
                  f"peak {row[24]:.3f} MB  {row[-1]}")
            del data
    write_csv(out / "sha256_results.csv", RAW_HEADER, raw)
    write_csv(out / "sha256_summary.csv", SUMMARY_HEADER, summary)
    return failures


def chunk_experiment(label: str, trials: int, warmup: int, out: Path) -> int:
    path, ref = load_dataset("BIN", label)
    size = path.stat().st_size
    fns = {cs: (lambda cs=cs: hash_file_chunked(path, cs)) if cs else (lambda: hash_file_whole(path))
           for cs in CHUNK_SIZES}
    for fn in fns.values():
        for _ in range(warmup):
            fn()
    times = {cs: [] for cs in CHUNK_SIZES}
    ok = {cs: 0 for cs in CHUNK_SIZES}
    for trial in range(trials):
        shift = trial % len(CHUNK_SIZES)
        for cs in CHUNK_SIZES[shift:] + CHUNK_SIZES[:shift]:
            digest, secs = timed(fns[cs])
            times[cs].append(secs * 1000)
            ok[cs] += compare_hashes(digest, ref)
    rows, failures = [], 0
    for cs in CHUNK_SIZES:
        s = summarise(times[cs])
        peak = peak_traced_mb(fns[cs])
        name = "whole file" if cs is None else (f"{cs // 1024} KiB" if cs < MIB else f"{cs // MIB} MiB")
        failures += trials - ok[cs]
        rows.append([f"BIN_{label}", size, name, size if cs is None else cs, trials,
                     s["mean"], s["min"], s["max"], s["std"], s["std"] / s["mean"] * 100,
                     size / MIB / (s["mean"] / 1000), peak,
                     f"PASS {ok[cs]}/{trials}" if ok[cs] == trials else f"FAIL {trials - ok[cs]}/{trials}"])
        print(f"  {name:<10} {s['mean']:9.3f} ms (sd {s['std']:.3f})  "
              f"{rows[-1][10]:8.1f} MB/s  peak traced {peak:9.3f} MB  {rows[-1][-1]}")
    write_csv(out / "sha256_chunk_size_experiment.csv", CHUNK_HEADER, rows)
    return failures


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--types", nargs="+", default=list(FILE_TYPES), choices=list(FILE_TYPES))
    ap.add_argument("--sizes", nargs="+", default=list(SIZES), choices=list(SIZES))
    ap.add_argument("--trials", type=int, default=MIN_TRIALS)
    ap.add_argument("--warmup", type=int, default=1)
    ap.add_argument("--cpu-window", type=float, default=0.25, help="seconds per CPU measurement")
    ap.add_argument("--chunk-file", default="50MB", choices=list(SIZES),
                    help="BIN file used for the chunk-size experiment")
    ap.add_argument("--out", type=Path, default=ROOT / "results")
    ap.add_argument("--quick", action="store_true",
                    help="smoke test: 3 trials, BIN, 1KB/1MB, output to results/quick (not for the report)")
    args = ap.parse_args()

    if args.quick:
        args.trials, args.types, args.sizes, args.chunk_file = 3, ["BIN"], ["1KB", "1MB"], "1MB"
        args.out = ROOT / "results" / "quick"
    elif args.trials < MIN_TRIALS:
        sys.exit(f"--trials must be at least {MIN_TRIALS} for reportable results (use --quick for a smoke test)")
    args.out = args.out.resolve()
    args.out.mkdir(parents=True, exist_ok=True)

    env = environment_info()
    for aes_only in ("AES-NI", "cryptography", "OpenSSL"):      # "OpenSSL" there is the one bundled with cryptography
        env.pop(aes_only, None)
    env.update({"hashlib backend": ssl.OPENSSL_VERSION,
                "SHA extensions (SHA-NI)": "not detectable from Python - check with Sysinternals Coreinfo "
                                           "(coreinfo64 -f, look for 'SHA')",
                "File types": args.types, "Input sizes": args.sizes,
                "Measured trials per configuration": args.trials,
                "Warm-up runs discarded per configuration": args.warmup,
                "Default read (chunk) size (bytes)": DEFAULT_CHUNK_SIZE,
                "Chunk-size experiment file": f"BIN {args.chunk_file}",
                "CPU sampling window (s)": args.cpu_window,
                "CPU measurement": cpu_method(),
                "Started": time.strftime("%Y-%m-%d %H:%M:%S")})
    print("Environment:")
    for k, v in env.items():
        print(f"  {k}: {v}")

    print("\nKnown-answer tests:")
    if not run_known_answer_tests(args.out / "sha256_known_answer_tests.csv"):
        sys.exit("Known-answer tests failed - benchmark aborted.")

    n = len(args.types) * len(args.sizes)
    print(f"\nBenchmark: {n} configurations x {args.trials} trials "
          f"(file = hash_file() with {DEFAULT_CHUNK_SIZE // 1024} KiB reads; in-memory = hash_bytes())")
    t0 = time.perf_counter()
    failures = benchmark(args.types, args.sizes, args.trials, args.warmup, args.cpu_window, args.out)

    print(f"\nChunk-size experiment (BIN {args.chunk_file}, {args.trials} trials each):")
    failures += chunk_experiment(args.chunk_file, args.trials, args.warmup, args.out)

    env["Finished"] = time.strftime("%Y-%m-%d %H:%M:%S")
    env["Benchmark duration (s)"] = round(time.perf_counter() - t0, 1)
    env["Digest verification failures"] = failures
    with open(args.out / "sha256_environment.txt", "w", encoding="utf-8") as f:
        f.writelines(f"{k}: {v}\n" for k, v in env.items())

    print(f"\nDone in {env['Benchmark duration (s)']} s. Digest verification failures: {failures}")
    print(f"Results written to {args.out}")
    sys.exit(1 if failures else 0)


if __name__ == "__main__":
    main()
