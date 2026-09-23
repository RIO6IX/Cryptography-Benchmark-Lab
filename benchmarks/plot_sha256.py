"""
Generate SHA-256 report graphs from the CSV files (never from hard-coded numbers).

    python -m benchmarks.plot_sha256                          # results/ -> results/graphs/
    python -m benchmarks.plot_sha256 --results results/quick

Figures (results/graphs/)
  sha256_time.png         Input size vs hashing time, per file type (log-log, +/-1 SD)
  sha256_cpu.png          Input size vs CPU utilisation (% of one logical core)
  sha256_memory.png       Input size vs peak traced memory (64 KiB reads)
  sha256_throughput.png   Input size vs throughput, file-based and in-memory
  sha256_chunk_size.png   Read size vs time and vs peak memory (two panels, 50 MB file)
  sha256_avalanche.png    Digest bits changed by single-bit input flips vs ideal Binomial(256, 0.5)

Inputs: sha256_summary.csv, sha256_chunk_size_experiment.csv, sha256_avalanche_distribution.csv
(missing optional files are skipped with a message).
"""
from __future__ import annotations

import argparse
import csv
import math
import sys
from pathlib import Path

import matplotlib.pyplot as plt

from benchmarks.plot_results import PLAIN, size_axis   # shared style (rcParams) and size axis

ROOT = Path(__file__).resolve().parent.parent
TYPE_ORDER = ["BIN", "TXT", "PDF", "JPG"]
TYPE_COLORS = {"BIN": "#2a78d6", "TXT": "#eb6834", "PDF": "#1baf7a", "JPG": "#eda100"}
TYPE_MARKERS = {"BIN": "o", "TXT": "s", "PDF": "^", "JPG": "D"}
NEUTRAL = "#52514e"
TEXT_COLUMNS = {"dataset_id", "file_type", "input_size", "sha256", "digest_consistency",
                "read_size", "filename", "verified"}


def load(path: Path, required: bool = True) -> list[dict] | None:
    if not path.exists():
        if required:
            sys.exit(f"{path} not found - run the benchmark first.")
        print(f"  ({path.name} not found - figure skipped)")
        return None
    with open(path, newline="", encoding="utf-8") as f:
        rows = list(csv.DictReader(f))
    for r in rows:
        for k, v in r.items():
            if k not in TEXT_COLUMNS:
                r[k] = float(v)
    return rows


def by_type(summary):
    types = [t for t in TYPE_ORDER if any(r["file_type"] == t for r in summary)]
    return {t: sorted((r for r in summary if r["file_type"] == t), key=lambda r: r["input_bytes"]) for t in types}


def save(fig, out: Path, name: str):
    fig.tight_layout()
    fig.savefig(out / name)
    plt.close(fig)
    print(f"  {out / name}")


def separate_close_ticks(ax):
    """5MB and 10MB sit close on a log axis; push their labels apart."""
    for label in ax.get_xticklabels():
        if label.get_text() == "5MB":
            label.set_horizontalalignment("right")
        elif label.get_text() == "10MB":
            label.set_horizontalalignment("left")


def line_plot(groups, y, err, ylabel, title, name, out, logy=False, ylim0=True, extra=None,
              ymax=None, legend_loc="best"):
    fig, ax = plt.subplots()
    ref = None
    for t, rows in groups.items():
        ref = rows
        ax.errorbar([r["input_MB"] for r in rows], [r[y] for r in rows],
                    yerr=[r[err] for r in rows] if err else None,
                    color=TYPE_COLORS[t], marker=TYPE_MARKERS[t], markersize=6, capsize=3, label=t)
    if extra:
        extra(ax)
    size_axis(ax, ref)
    separate_close_ticks(ax)
    if logy:
        ax.set_yscale("log")
        ax.yaxis.set_major_formatter(PLAIN)
    elif ylim0:
        ax.set_ylim(bottom=0, top=ymax)
    ax.set_ylabel(ylabel)
    ax.set_title(title)
    ax.grid(True, which="major", alpha=0.8)
    ax.legend(title="File type", loc=legend_loc)
    save(fig, out, name)


def chunk_plot(rows, out: Path):
    names = [r["read_size"] for r in rows]
    fig, (a1, a2) = plt.subplots(1, 2, figsize=(9, 4.3))
    err = {"ecolor": NEUTRAL, "elinewidth": 1.2, "capsize": 4}
    a1.bar(names, [r["mean_ms"] for r in rows], yerr=[r["std_ms"] for r in rows], error_kw=err,
           color=TYPE_COLORS["BIN"], width=0.6)
    for i, r in enumerate(rows):
        a1.annotate(f"{r['mean_ms']:.3g}", (i, r["mean_ms"] + r["std_ms"]), textcoords="offset points",
                    xytext=(0, 4), ha="center", fontsize=8, color=NEUTRAL)
    a1.set_ylim(0, max(r["mean_ms"] + r["std_ms"] for r in rows) * 1.18)
    a1.set_ylabel("Mean hashing time (ms), error bars = ±1 SD")
    a1.set_title("Hashing time")
    a2.bar(names, [r["peak_traced_MB"] for r in rows], color=TYPE_COLORS["BIN"], width=0.6)
    for i, r in enumerate(rows):
        a2.annotate(f"{r['peak_traced_MB']:.3g}", (i, r["peak_traced_MB"]), textcoords="offset points",
                    xytext=(0, 4), ha="center", fontsize=8, color=NEUTRAL)
    a2.set_yscale("log")
    a2.yaxis.set_major_formatter(PLAIN)
    a2.set_ylim(top=max(r["peak_traced_MB"] for r in rows) * 3)
    a2.set_ylabel("Peak traced memory (MB, log scale)")
    a2.set_title("Peak memory")
    for ax in (a1, a2):
        ax.set_xlabel("Read (chunk) size")
        ax.grid(True, axis="y", alpha=0.8)
        ax.set_axisbelow(True)
    mb = rows[0]["input_bytes"] / 1024**2
    fig.suptitle(f"Effect of Read Size on SHA-256 Hashing - {mb:g} MB BIN file, n={int(rows[0]['trials'])}",
                 fontweight="bold", fontsize=11)
    save(fig, out, "sha256_chunk_size.png")


def avalanche_plot(rows, out: Path):
    d = [int(r["differing_bits_of_256"]) for r in rows]
    n = len(d)
    mean = sum(d) / n
    sd = math.sqrt(sum((x - mean) ** 2 for x in d) / (n - 1))
    fig, ax = plt.subplots()
    lo, hi = min(min(d), 96), max(max(d), 160)
    ax.hist(d, bins=range(lo, hi + 2), color=TYPE_COLORS["BIN"], edgecolor="white", linewidth=0.5,
            label=f"Observed (n={n}): mean {mean:.2f}, SD {sd:.2f}")
    xs = range(lo, hi + 1)
    expected = [n * math.comb(256, k) / 2**256 for k in xs]
    ax.plot([x + 0.5 for x in xs], expected, color=NEUTRAL, linewidth=1.5,
            label="Ideal Binomial(256, 0.5): mean 128, SD 8")
    ax.axvline(128.5, color=NEUTRAL, linestyle="--", linewidth=1)
    ax.set_xlabel("Digest bits changed (of 256) by a single-bit input flip")
    ax.set_ylabel(f"Number of trials (of {n})")
    ax.set_title("SHA-256 Avalanche Effect - single-bit changes to a 1 KB input")
    ax.grid(True, axis="y", alpha=0.8)
    ax.set_axisbelow(True)
    ax.set_ylim(0, max(d.count(k) for k in set(d)) * 1.4)     # headroom for the legend
    ax.legend(loc="upper left", frameon=True, facecolor="white", edgecolor="none", framealpha=1)
    save(fig, out, "sha256_avalanche.png")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--results", type=Path, default=ROOT / "results")
    args = ap.parse_args()
    res = args.results.resolve()
    out = res / "graphs"
    out.mkdir(parents=True, exist_ok=True)

    summary = load(res / "sha256_summary.csv")
    groups = by_type(summary)
    n = int(summary[0]["trials"])
    print("Writing graphs:")

    line_plot(groups, "mean_ms", "std_ms", "Mean hashing time (ms, log scale), ±1 SD",
              f"Input Size vs SHA-256 Hashing Time (file, 64 KiB reads), n={n}",
              "sha256_time.png", out, logy=True)
    line_plot(groups, "cpu_mean_pct", "cpu_std_pct", "Mean process CPU (% of one logical core), ±1 SD",
              "Input Size vs CPU Usage - SHA-256 file hashing", "sha256_cpu.png", out,
              ymax=110, legend_loc="lower right")
    line_plot(groups, "peak_mean_MB", None, "Mean peak traced memory (MB)",
              "Input Size vs Memory Usage - SHA-256, 64 KiB reads", "sha256_memory.png", out)

    def in_memory(ax):
        rows = groups.get("BIN") or next(iter(groups.values()))
        ax.plot([r["input_MB"] for r in rows], [r["inmemory_throughput_MBps"] for r in rows],
                color=NEUTRAL, linestyle="--", marker="x", markersize=7,
                label=f"{rows[0]['file_type']} in memory (no file I/O)")
    line_plot(groups, "throughput_MBps", None, "Throughput (MB/s, 1 MB = 1,048,576 B)",
              "Input Size vs SHA-256 Throughput", "sha256_throughput.png", out, extra=in_memory)

    chunks = load(res / "sha256_chunk_size_experiment.csv", required=False)
    if chunks:
        chunk_plot(chunks, out)
    aval = load(res / "sha256_avalanche_distribution.csv", required=False)
    if aval:
        avalanche_plot(aval, out)


if __name__ == "__main__":
    main()
