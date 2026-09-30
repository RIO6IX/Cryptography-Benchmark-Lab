"""
Unified benchmark of all algorithms (IE3082 Cryptography - Member 4: Benchmarking + Integration).

    python -m benchmarks.benchmark_all                     # full run -> results/combined_*.csv
    python -m benchmarks.benchmark_all --types BIN         # binary data only (much faster)
    python -m benchmarks.benchmark_all --quick             # smoke test -> results/quick/ (not for the report)
    python -m benchmarks.benchmark_all --algorithms aes sha256

Scenarios (fair-comparison design, see README_BENCHMARK.md)
  keygen         RSA key generation per key size (no payload)
  small_payload  32 B and 190 B (RSA-2048 OAEP limit with SHA-256): AES-GCM,
                 SHA-256 and RSA (encrypt/decrypt/sign/verify) on the same bytes
  size_sweep     AES-GCM and SHA-256 on the shared datasets (4 types x 6 sizes).
                 RSA is not in the sweep: RSA-OAEP cannot encrypt more than
                 k - 66 bytes per operation
  hybrid         RSA-wrapped AES-256 key + AES-GCM file encryption + SHA-256
                 digest, each step timed (only when the RSA module exists)

All algorithm/variant pairs of a configuration run on the same payload in an
order that rotates each trial. Method details: benchmarks/framework.py.

Outputs (in results/ or --out)
  combined_raw_trials.csv    one row per trial and operation
  combined_summary.csv       one row per configuration (common schema)
  environment_combined.txt   hardware/software/settings, self-checks, skipped items
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import sys
import time
from functools import lru_cache
from pathlib import Path

from benchmarks.adapters import ADAPTER_NAMES, build_adapters
from benchmarks.framework import (HYBRID, KEYGEN, MIN_TRIALS, RAW_FIELDS, SIZE_SWEEP, SMALL_PAYLOAD,
                                  SMOKE_MIN_TRIALS, SUMMARY_FIELDS, RunSettings, run_configuration,
                                  units_for, write_csv)
from benchmarks.measure import cpu_method, environment_info
from datasets.generate_test_data import FILE_TYPES, MANIFEST, SIZES, dataset_path

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_SMALL_SIZES = [32, 190]                  # 32 B = one AES-256 key; 190 B = RSA-2048 OAEP limit
DEFAULT_HYBRID_SIZES = ["1KB", "1MB", "10MB"]
SMALL_SEED = b"IE3082-M4-small-payload"

RAW_CSV = "combined_raw_trials.csv"
SUMMARY_CSV = "combined_summary.csv"
ENV_TXT = "environment_combined.txt"


# --------------------------------------------------------------- inputs
def small_payload(size: int) -> bytes:
    """Deterministic random-looking bytes (SHAKE-256, fixed seed), like the BIN datasets."""
    return hashlib.shake_256(SMALL_SEED + size.to_bytes(8, "big")).digest(size)


@lru_cache(maxsize=1)
def manifest_digests() -> dict[str, str]:
    if not MANIFEST.exists():
        return {}
    with open(MANIFEST, newline="") as f:
        return {r["path"]: r["sha256"] for r in csv.DictReader(f)}


def load_dataset(ftype: str, label: str) -> tuple[bytes, str | None]:
    """Payload bytes of a shared dataset file and its trusted reference digest (manifest.csv)."""
    path = dataset_path(ftype, label)
    if not path.exists():
        sys.exit(f"Missing dataset {path}. Run: python -m datasets.generate_test_data")
    data = path.read_bytes()                     # read once; file I/O is never timed
    if len(data) != SIZES[label]:
        sys.exit(f"{path} is {len(data)} bytes, expected {SIZES[label]}. Regenerate the datasets.")
    return data, manifest_digests().get(path.relative_to(ROOT).as_posix())


# --------------------------------------------------------------- run
def run_all(adapters, args, settings: RunSettings) -> tuple[list, list, list, int]:
    raw, summary, skipped, failures = [], [], [], 0

    def run(units, data, meta):
        nonlocal failures
        res = run_configuration(units, data, meta, settings)
        raw.extend(res.raw)
        summary.extend(res.summary)
        skipped.extend(res.skipped)
        failures += res.failures

    units = units_for(adapters, KEYGEN)
    if units:
        print("\n[keygen] RSA key generation")
        run(units, b"", {"scenario": KEYGEN, "file_type": "", "size_label": ""})

    units = units_for(adapters, SMALL_PAYLOAD)
    if units and args.small_sizes:
        print(f"\n[small_payload] {', '.join(f'{n} B' for n in args.small_sizes)} - every algorithm on the same bytes")
        for n in args.small_sizes:
            run(units, small_payload(n), {"scenario": SMALL_PAYLOAD, "file_type": "BIN", "size_label": f"{n}B"})

    units = units_for(adapters, SIZE_SWEEP)
    if units:
        print(f"\n[size_sweep] {len(args.types)} types x {len(args.sizes)} sizes")
        for ftype in args.types:
            for label in args.sizes:
                data, ref = load_dataset(ftype, label)
                run(units, data, {"scenario": SIZE_SWEEP, "file_type": ftype, "size_label": label,
                                  "reference_sha256": ref})
                del data

    units = units_for(adapters, HYBRID)
    if units and args.hybrid_sizes:
        print(f"\n[hybrid] RSA key wrap + AES-256-GCM + SHA-256, {args.hybrid_type} "
              f"{', '.join(args.hybrid_sizes)}")
        for label in args.hybrid_sizes:
            data, ref = load_dataset(args.hybrid_type, label)
            run(units, data, {"scenario": HYBRID, "file_type": args.hybrid_type, "size_label": label,
                              "reference_sha256": ref})
            del data
    return raw, summary, skipped, failures


def parse_args(argv=None) -> argparse.Namespace:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--algorithms", nargs="+", default=list(ADAPTER_NAMES), choices=ADAPTER_NAMES,
                    help="adapters to run (default: all; RSA and hybrid are skipped if the RSA module is missing)")
    ap.add_argument("--types", nargs="+", default=list(FILE_TYPES), choices=list(FILE_TYPES),
                    help="dataset file types for the size sweep")
    ap.add_argument("--sizes", nargs="+", default=list(SIZES), choices=list(SIZES),
                    help="dataset sizes for the size sweep")
    ap.add_argument("--small-sizes", nargs="*", type=int, default=DEFAULT_SMALL_SIZES, metavar="BYTES",
                    help="payload sizes (bytes) for the small-payload head-to-head (default: 32 190)")
    ap.add_argument("--hybrid-sizes", nargs="*", default=DEFAULT_HYBRID_SIZES, choices=list(SIZES),
                    help="dataset sizes for the hybrid scenario (default: 1KB 1MB 10MB)")
    ap.add_argument("--hybrid-type", default="BIN", choices=list(FILE_TYPES))
    ap.add_argument("--trials", type=int, default=MIN_TRIALS, help=f"measured trials (minimum {MIN_TRIALS})")
    ap.add_argument("--warmup", type=int, default=1, help="discarded warm-up runs per configuration")
    ap.add_argument("--cpu-window", type=float, default=None,
                    help="seconds per CPU measurement (default 0.25; 0.05 with --quick)")
    ap.add_argument("--out", type=Path, default=None, help="output folder (default: results/)")
    ap.add_argument("--quick", action="store_true",
                    help="smoke test: 3 trials, BIN 1KB/1MB, hybrid 1KB, output to results/quick (not for the report)")
    args = ap.parse_args(argv)
    if args.quick:
        args.trials, args.types, args.sizes, args.hybrid_sizes = 3, ["BIN"], ["1KB", "1MB"], ["1KB"]
        args.out = args.out or ROOT / "results" / "quick"
        args.cpu_window = args.cpu_window or 0.05
    elif args.trials < MIN_TRIALS:
        ap.error(f"--trials must be at least {MIN_TRIALS} for reportable results (use --quick for a smoke test)")
    if args.quick and args.trials < SMOKE_MIN_TRIALS:
        ap.error(f"--trials must be at least {SMOKE_MIN_TRIALS}")
    if any(n < 1 for n in args.small_sizes):
        ap.error("--small-sizes must be positive byte counts")
    args.out = (args.out or ROOT / "results").resolve()
    args.cpu_window = args.cpu_window or 0.25
    return args


def main(argv=None) -> int:
    args = parse_args(argv)
    settings = RunSettings(trials=args.trials, warmup=args.warmup, cpu_window=args.cpu_window,
                           smoke=args.quick).validate()
    args.out.mkdir(parents=True, exist_ok=True)

    aset = build_adapters(args.algorithms)
    for w in aset.warnings:
        print(w, file=sys.stderr)
    if aset.fatal:
        print(f"Self-check failed for required adapter(s) {aset.fatal} - benchmark aborted.", file=sys.stderr)
        return 1

    env = environment_info()
    for a in aset.adapters:
        env.update(a.environment())
    if "rsa" in aset.skipped or "hybrid" in aset.skipped:
        env["RSA module"] = f"not benchmarked - {aset.skipped.get('rsa') or aset.skipped.get('hybrid')}"
    env.update({
        "Run type": "QUICK SMOKE TEST - not for the report" if args.quick else "full",
        "Algorithms benchmarked": [a.name for a in aset.adapters],
        "Adapters skipped": aset.skipped or "none",
        "Self-checks": aset.checks,
        "Size sweep": f"types {args.types}, sizes {args.sizes}",
        "Small payloads (bytes)": args.small_sizes,
        "Hybrid scenario": f"{args.hybrid_type} {args.hybrid_sizes}" if "hybrid" not in aset.skipped else "skipped",
        "Measured trials per configuration": args.trials,
        "Warm-up runs discarded per configuration": args.warmup,
        "Order": "all algorithm/variant pairs of a configuration, rotated by one position per trial",
        "CPU sampling window (s)": args.cpu_window,
        "CPU measurement": cpu_method(),
        "Memory measurement": "tracemalloc peak of Python allocations per operation (separate run) + process RSS",
        "Started": time.strftime("%Y-%m-%d %H:%M:%S"),
    })
    print("Environment:")
    for k, v in env.items():
        print(f"  {k}: {v}")

    t0 = time.perf_counter()
    raw, summary, skipped, failures = run_all(aset.adapters, args, settings)

    write_csv(args.out / RAW_CSV, RAW_FIELDS, raw)
    write_csv(args.out / SUMMARY_CSV, SUMMARY_FIELDS, summary)
    env["Finished"] = time.strftime("%Y-%m-%d %H:%M:%S")
    env["Benchmark duration (s)"] = round(time.perf_counter() - t0, 1)
    env["Configurations (summary rows)"] = len(summary)
    env["Operations skipped (input limit)"] = skipped or "none"
    env["Correctness failures (trials)"] = failures
    with open(args.out / ENV_TXT, "w", encoding="utf-8") as f:
        f.writelines(f"{k}: {v}\n" for k, v in env.items())

    for s in skipped:
        print(f"  skipped: {s}")
    print(f"\nDone in {env['Benchmark duration (s)']} s. {len(summary)} summary rows. "
          f"Correctness failures: {failures}")
    print(f"Results written to {args.out}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
