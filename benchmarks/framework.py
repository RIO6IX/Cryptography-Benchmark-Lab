"""
Common benchmarking framework (IE3082 Cryptography - Member 4: Benchmarking + Integration).

Every algorithm is wrapped in a thin AlgorithmAdapter (benchmarks/adapters/) and
one generic runner measures all of them the same way. Timing, CPU and memory
come from benchmarks/measure.py, the helpers already used by benchmark_aes.py and
benchmark_sha256.py, so the combined results are methodologically consistent
with the per-component CSVs.

Method per configuration (one input payload, one or more algorithm/variant units)
  1. Warm-up: every operation of every unit runs `warmup` times; discarded.
  2. N >= 10 measured trials. In each trial every unit runs once, in an order
     that rotates by one position per trial (as in benchmark_aes), so slow drift
     (CPU temperature, turbo, background load) is shared between algorithms
     instead of biasing whichever runs last.
  3. Per (trial, unit): setup() with a fresh key (not timed) -> each operation
     timed once with measure.timed (perf_counter, GC disabled) -> correctness
     check -> separate tracemalloc run per operation -> separate CPU run per
     operation (measure.cpu_percent) -> process RSS.
  4. Per operation: mean, min, max, sample SD (n - 1), CV = SD / mean, 95 %
     confidence interval half-width (Student t), and throughput = MB / mean time
     (1 MB = 1,048,576 B, as in the AES and SHA-256 CSVs).
"""
from __future__ import annotations

import csv
import math
import statistics
from abc import ABC, abstractmethod
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Iterable, Sequence

from benchmarks.measure import MIB, cpu_percent, peak_traced_mb, rss_mb, summarise, timed

MIN_TRIALS = 10               # reportable runs (same rule as benchmark_aes / benchmark_sha256)
SMOKE_MIN_TRIALS = 2          # --quick smoke tests; 2 is the minimum for a sample SD
HIGH_CV_PCT = 10.0            # configurations above this CV are flagged as unstable

# Scenarios (see README_BENCHMARK.md, "Fair-comparison design")
KEYGEN = "keygen"                 # RSA key generation, no payload
SMALL_PAYLOAD = "small_payload"   # 32 B / 190 B head-to-head: every algorithm can process it
SIZE_SWEEP = "size_sweep"         # shared datasets 1 KB - 50 MB (AES-GCM and SHA-256)
HYBRID = "hybrid"                 # RSA-wrapped AES-256 key + AES-GCM + SHA-256 digest
SCENARIOS = (KEYGEN, SMALL_PAYLOAD, SIZE_SWEEP, HYBRID)

CATEGORIES = ("symmetric", "asymmetric", "hash", "hybrid")

RAW_FIELDS = ["scenario", "algorithm", "variant", "category", "operation", "file_type", "size_label",
              "size_bytes", "trial", "order_position", "time_ms", "throughput_mbps", "cpu_pct",
              "cpu_os_pct", "peak_mem_mb", "rss_mb", "verified"]

# Units: times in ms; cv in % of the mean; ci95 = half-width of the 95 % CI of the mean, in ms;
# throughput_mbps in MB/s (1 MB = 1,048,576 B; empty when the operation has no payload);
# cpu in % of ONE logical core; peak_mem_mb = mean tracemalloc peak; rss_mb = mean process RSS.
SUMMARY_FIELDS = ["scenario", "algorithm", "variant", "category", "operation", "file_type", "size_label",
                  "size_bytes", "trials", "mean_ms", "min_ms", "max_ms", "sd_ms", "cv", "ci95",
                  "throughput_mbps", "cpu_pct_mean", "cpu_pct_sd", "peak_mem_mb", "rss_mb", "correctness"]

TEXT_FIELDS = {"scenario", "algorithm", "variant", "category", "operation", "file_type", "size_label",
               "correctness", "verified"}


# --------------------------------------------------------------- statistics
# Two-sided 95 % critical values of Student's t (0.975 quantile), df = 1..30.
_T975 = {1: 12.706, 2: 4.303, 3: 3.182, 4: 2.776, 5: 2.571, 6: 2.447, 7: 2.365, 8: 2.306,
         9: 2.262, 10: 2.228, 11: 2.201, 12: 2.179, 13: 2.160, 14: 2.145, 15: 2.131,
         16: 2.120, 17: 2.110, 18: 2.101, 19: 2.093, 20: 2.086, 21: 2.080, 22: 2.074,
         23: 2.069, 24: 2.064, 25: 2.060, 26: 2.056, 27: 2.052, 28: 2.048, 29: 2.045, 30: 2.042}


def t_critical(df: int) -> float:
    """0.975 quantile of Student's t with `df` degrees of freedom (95 % two-sided).

    Exact table values up to df = 30; above that the Cornish-Fisher expansion
    around the normal quantile, which is accurate to about 1e-4 there.
    """
    if isinstance(df, bool) or not isinstance(df, int) or df < 1:
        raise ValueError(f"degrees of freedom must be a positive integer, got {df!r}")
    if df in _T975:
        return _T975[df]
    z = statistics.NormalDist().inv_cdf(0.975)
    return (z + (z**3 + z) / (4 * df) + (5 * z**5 + 16 * z**3 + 3 * z) / (96 * df**2)
            + (3 * z**7 + 19 * z**5 + 17 * z**3 - 15 * z) / (384 * df**3))


@dataclass(frozen=True)
class Stats:
    n: int
    mean: float
    min: float
    max: float
    sd: float                        # sample SD (n - 1)
    cv_pct: float                    # SD / mean x 100
    ci95: float                      # half-width of the 95 % CI of the mean
    throughput_mbps: float | None    # only when a payload size is given


def throughput_mbps(size_bytes: int, seconds: float) -> float | None:
    """MB/s with 1 MB = 1,048,576 B; None when there is no payload."""
    if not size_bytes or seconds <= 0:
        return None
    return size_bytes / MIB / seconds


def describe(values_ms: Sequence[float], size_bytes: int = 0) -> Stats:
    """Descriptive statistics of per-trial times (ms), built on measure.summarise."""
    values = list(values_ms)
    if not values:
        raise ValueError("describe() needs at least one value")
    s = summarise(values)
    n = len(values)
    ci = t_critical(n - 1) * s["std"] / math.sqrt(n) if n > 1 else 0.0
    cv = s["std"] / s["mean"] * 100 if s["mean"] > 0 else 0.0
    return Stats(n, s["mean"], s["min"], s["max"], s["std"], cv, ci,
                 throughput_mbps(size_bytes, s["mean"] / 1000))


def correctness_label(passed: int, total: int) -> str:
    """Same wording as the AES and SHA-256 summaries: 'PASS 10/10' or 'FAIL 2/10'."""
    return f"PASS {passed}/{total}" if passed == total else f"FAIL {total - passed}/{total}"


# --------------------------------------------------------------- adapter interface
@dataclass(frozen=True)
class Operation:
    """One timed operation of an algorithm.

    `bind(ctx, data)` returns the zero-argument callable that is timed. Binding
    happens outside the timed region, so the timed call is only the library call
    (e.g. functools.partial(cipher.encrypt, data, aad), exactly as benchmark_aes
    times it). Outputs of earlier operations of the same trial are available as
    ctx["outputs"][name], so decrypt can bind to the ciphertext from encrypt.
    """
    name: str
    bind: Callable[[dict, bytes], Callable[[], Any]]
    bulk: bool = True             # processes the whole payload -> throughput is reported
    size_limited: bool = False    # subject to AlgorithmAdapter.max_input_size() (e.g. RSA-OAEP)


class AlgorithmAdapter(ABC):
    """Thin wrapper that exposes one algorithm to the generic runner.

    Adapters contain no measurement code and no cryptography of their own; they
    only call the group members' modules in src/.
    """
    name: str = ""            # e.g. "AES-GCM"
    category: str = ""        # one of CATEGORIES

    def __init__(self) -> None:
        self.unavailable_reason: str | None = None

    @property
    def available(self) -> bool:
        return self.unavailable_reason is None

    @property
    @abstractmethod
    def variants(self) -> tuple[str, ...]:
        """e.g. ("AES-128", "AES-192", "AES-256")."""

    @abstractmethod
    def operations(self, variant: str, scenario: str) -> list[Operation]:
        """Operations to time for this variant in this scenario ([] = not part of it)."""

    def max_input_size(self, variant: str) -> int | None:
        """Largest payload (bytes) a size-limited operation accepts; None = unlimited."""
        return None

    @abstractmethod
    def setup(self, variant: str, data: bytes, meta: dict) -> dict:
        """Per-trial context (fresh keys etc.). Called outside the timed region."""

    @abstractmethod
    def verify(self, ctx: dict, data: bytes, outputs: dict[str, Any]) -> bool:
        """Correctness of one trial, from the outputs of the timed operations."""

    def self_check(self) -> str:
        """Quick functional check before benchmarking; raise on failure, return a description."""
        return "no self-check defined"

    def environment(self) -> dict[str, str]:
        """Extra lines for environment_combined.txt (library versions, limits...)."""
        return {}


@dataclass(frozen=True)
class Unit:
    """One (adapter, variant) pair taking part in a configuration."""
    adapter: AlgorithmAdapter
    variant: str


def units_for(adapters: Iterable[AlgorithmAdapter], scenario: str) -> list[Unit]:
    """All available (adapter, variant) pairs that have operations in `scenario`."""
    return [Unit(a, v) for a in adapters if a.available for v in a.variants if a.operations(v, scenario)]


# --------------------------------------------------------------- runner
@dataclass(frozen=True)
class RunSettings:
    trials: int = MIN_TRIALS
    warmup: int = 1
    cpu_window: float = 0.25      # seconds per CPU measurement (as in the other benchmarks)
    smoke: bool = False           # --quick: allows fewer than MIN_TRIALS trials

    def validate(self) -> "RunSettings":
        minimum = SMOKE_MIN_TRIALS if self.smoke else MIN_TRIALS
        if self.trials < minimum:
            raise ValueError(f"trials must be at least {minimum} "
                             f"({'smoke test' if self.smoke else 'reportable results; use --quick for a smoke test'})")
        if self.warmup < 0:
            raise ValueError("warmup must be >= 0")
        if self.cpu_window <= 0:
            raise ValueError("cpu_window must be > 0")
        return self


@dataclass
class ConfigResult:
    raw: list[dict]
    summary: list[dict]
    skipped: list[str]            # operations not run (e.g. payload above the RSA-OAEP limit)
    failures: int                 # trials whose correctness check failed


def plan(units: Sequence[Unit], data: bytes, meta: dict) -> tuple[list[tuple[Unit, list[Operation]]], list[str]]:
    """Operations per unit for this payload; size-limited operations above the limit are skipped."""
    planned, skipped = [], []
    for u in units:
        limit = u.adapter.max_input_size(u.variant)
        kept = []
        for op in u.adapter.operations(u.variant, meta["scenario"]):
            if op.size_limited and limit is not None and len(data) > limit:
                skipped.append(f"{u.variant} {op.name} at {meta.get('size_label') or len(data)}: "
                               f"{len(data)} B exceeds the {limit} B input limit")
            else:
                kept.append(op)
        if kept:
            planned.append((u, kept))
    return planned, skipped


def _execute(unit: Unit, ops: list[Operation], data: bytes, meta: dict, measure: bool) -> tuple[dict, dict]:
    """setup() then every operation once, in order. Returns (ctx, seconds per operation)."""
    ctx = unit.adapter.setup(unit.variant, data, meta)
    outputs = ctx.setdefault("outputs", {})
    seconds = {}
    for op in ops:
        call = op.bind(ctx, data)
        if measure:
            outputs[op.name], seconds[op.name] = timed(call)
        else:
            outputs[op.name] = call()
    return ctx, seconds


def run_trial(unit: Unit, ops: list[Operation], data: bytes, meta: dict, cpu_window: float) -> dict:
    """One measured trial of one unit: timing, correctness, then separate memory and CPU runs."""
    ctx, seconds = _execute(unit, ops, data, meta, measure=True)
    try:
        verified = bool(unit.adapter.verify(ctx, data, ctx["outputs"]))
    except Exception:                    # a failing check must be recorded as FAIL, not crash the run
        verified = False
    peaks = {op.name: peak_traced_mb(op.bind(ctx, data)) for op in ops}
    cpus = {op.name: cpu_percent(op.bind(ctx, data), cpu_window) for op in ops}
    return {"seconds": seconds, "peak": peaks, "cpu": cpus, "rss": rss_mb(), "verified": verified}


def run_configuration(units: Sequence[Unit], data: bytes, meta: dict, settings: RunSettings,
                      log: Callable[[str], None] | None = print) -> ConfigResult:
    """Benchmark every unit on one payload. `meta` needs scenario, file_type and size_label;
    it is also passed to setup() (e.g. a trusted reference digest)."""
    settings.validate()
    planned, skipped = plan(units, data, meta)
    if not planned:
        return ConfigResult([], [], skipped, 0)

    for _ in range(settings.warmup):                          # warm-up, discarded
        for unit, ops in planned:
            _execute(unit, ops, data, meta, measure=False)

    per_unit: dict[int, list[dict]] = {i: [] for i in range(len(planned))}
    raw: list[dict] = []
    size = len(data)
    for trial in range(settings.trials):
        shift = trial % len(planned)
        order = list(range(len(planned)))[shift:] + list(range(len(planned)))[:shift]
        for position, i in enumerate(order, start=1):
            unit, ops = planned[i]
            t = run_trial(unit, ops, data, meta, settings.cpu_window)
            per_unit[i].append(t)
            for op in ops:
                secs = t["seconds"][op.name]
                raw.append(_row(RAW_FIELDS, meta, unit, op, size, {
                    "trial": trial + 1, "order_position": position, "time_ms": secs * 1000,
                    "throughput_mbps": throughput_mbps(size, secs) if op.bulk else None,
                    "cpu_pct": t["cpu"][op.name][0], "cpu_os_pct": t["cpu"][op.name][1],
                    "peak_mem_mb": t["peak"][op.name], "rss_mb": t["rss"],
                    "verified": "PASS" if t["verified"] else "FAIL"}))

    summary, failures = [], 0
    for i, (unit, ops) in enumerate(planned):
        trials = per_unit[i]
        passed = sum(t["verified"] for t in trials)
        failures += len(trials) - passed
        for op in ops:
            st = describe([t["seconds"][op.name] * 1000 for t in trials], size if op.bulk else 0)
            cpu = summarise([t["cpu"][op.name][0] for t in trials])
            row = _row(SUMMARY_FIELDS, meta, unit, op, size, {
                "trials": st.n, "mean_ms": st.mean, "min_ms": st.min, "max_ms": st.max, "sd_ms": st.sd,
                "cv": st.cv_pct, "ci95": st.ci95, "throughput_mbps": st.throughput_mbps,
                "cpu_pct_mean": cpu["mean"], "cpu_pct_sd": cpu["std"],
                "peak_mem_mb": statistics.mean(t["peak"][op.name] for t in trials),
                "rss_mb": statistics.mean(t["rss"] for t in trials),
                "correctness": correctness_label(passed, len(trials))})
            summary.append(row)
            if log:
                log(format_summary_line(row))
    return ConfigResult(raw, summary, skipped, failures)


def _row(fields: list[str], meta: dict, unit: Unit, op: Operation, size: int, values: dict) -> dict:
    base = {"scenario": meta["scenario"], "algorithm": unit.adapter.name, "variant": unit.variant,
            "category": unit.adapter.category, "operation": op.name,
            "file_type": meta.get("file_type", ""), "size_label": meta.get("size_label", ""),
            "size_bytes": size}
    base.update(values)
    return {k: base.get(k) for k in fields}


def format_summary_line(row: dict) -> str:
    tp = row["throughput_mbps"]
    tp_text = f"{tp:10.1f} MB/s" if tp is not None else " " * 15
    return (f"  {row['variant']:<17} {row['operation']:<13} {row['file_type'] or '-':<4} "
            f"{row['size_label'] or '-':>6}: {row['mean_ms']:11.4f} ms (sd {row['sd_ms']:.4f}, "
            f"CV {row['cv']:5.1f}%) {tp_text}  CPU {row['cpu_pct_mean']:5.1f}%  {row['correctness']}")


# --------------------------------------------------------------- CSV helpers
def write_csv(path: Path, fields: list[str], rows: Iterable[dict]) -> None:
    """Write dict rows; floats as 6 significant digits (as in the other result CSVs), None as ''."""
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        for row in rows:
            w.writerow({k: ("" if v is None else f"{v:.6g}" if isinstance(v, float) else v)
                        for k, v in row.items()})


def read_csv(path: Path) -> list[dict]:
    """Read a combined CSV back; numeric columns become float, empty cells None."""
    with open(path, newline="", encoding="utf-8") as f:
        rows = list(csv.DictReader(f))
    for r in rows:
        for k, v in r.items():
            if k in TEXT_FIELDS:
                continue
            r[k] = None if v == "" else float(v)
    return rows


def check_schema(path: Path, fields: list[str]) -> None:
    """Raise ValueError unless the CSV header is exactly `fields`."""
    with open(path, newline="", encoding="utf-8") as f:
        header = next(csv.reader(f), [])
    if header != fields:
        raise ValueError(f"{path.name}: unexpected columns {header}, expected {fields}")
