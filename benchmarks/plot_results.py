"""
Generate report graphs from the benchmark CSV files (never from hard-coded numbers).

    python -m benchmarks.plot_results                       # BIN data, results/ -> results/graphs/
    python -m benchmarks.plot_results --file-type TXT
    python -m benchmarks.plot_results --results results/quick

Figures
  fig1_enc_time.png         Input size vs encryption time (log-log, +/-1 SD)
  fig2_dec_time.png         Input size vs decryption time (log-log, +/-1 SD)
  fig3_keysize_time.png     AES-128/192/256 encryption and decryption time at one size (+/-1 SD)
  fig4_cpu.png              Input size vs CPU utilisation (% of one logical core)
  fig5_memory.png           Input size vs peak traced memory (log-log)
  fig6_throughput.png       Input size vs encryption throughput (MB/s)
  fig7_filetype.png         Encryption time by file type at one size and key (if >1 type benchmarked)
"""
from __future__ import annotations

import argparse
import csv
import sys
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
from matplotlib.ticker import FuncFormatter  # noqa: E402

PLAIN = FuncFormatter(lambda v, _: f"{v:g}")
ROOT = Path(__file__).resolve().parent.parent
KEY_COLORS = {128: "#2a78d6", 192: "#eb6834", 256: "#1baf7a"}
KEY_MARKERS = {128: "o", 192: "s", 256: "^"}
ENC_COLOR, DEC_COLOR = "#2a78d6", "#eb6834"

plt.rcParams.update({
    "figure.figsize": (7, 4.3), "figure.dpi": 100, "savefig.dpi": 200,
    "font.size": 10, "axes.titlesize": 11, "axes.titleweight": "bold",
    "axes.spines.top": False, "axes.spines.right": False,
    "axes.edgecolor": "#8a8984", "axes.labelcolor": "#0b0b0b",
    "xtick.color": "#52514e", "ytick.color": "#52514e",
    "grid.color": "#d9d8d3", "grid.linewidth": 0.6, "lines.linewidth": 2,
    "legend.frameon": False,
})


def load(path: Path) -> list[dict]:
    if not path.exists():
        sys.exit(f"{path} not found - run the benchmark first.")
    with open(path, newline="") as f:
        rows = list(csv.DictReader(f))
    for r in rows:
        for k, v in r.items():
            try:
                r[k] = float(v) if k not in ("key_size", "file_type", "input_size", "correctness", "verified") else v
            except ValueError:
                pass
    return rows


def series(summary, ftype, bits):
    rows = [r for r in summary if r["file_type"] == ftype and int(r["key_bits"]) == bits]
    return sorted(rows, key=lambda r: r["input_bytes"])


def size_axis(ax, rows):
    ax.set_xscale("log")
    ax.set_xticks([r["input_MB"] for r in rows], [r["input_size"] for r in rows])
    ax.minorticks_off()
    ax.set_xlabel("Input size (log scale; 1 KB = 1024 B, 1 MB = 1,048,576 B)")


def line_plot(summary, ftype, keys, y, err, ylabel, title, fname, out, logy=True, ylim0=False):
    fig, ax = plt.subplots()
    ref = None
    for bits in keys:
        rows = series(summary, ftype, bits)
        if not rows:
            continue
        ref = rows
        ax.errorbar([r["input_MB"] for r in rows], [r[y] for r in rows],
                    yerr=[r[err] for r in rows] if err else None,
                    color=KEY_COLORS[bits], marker=KEY_MARKERS[bits], markersize=6,
                    capsize=3, label=f"AES-{bits}-GCM")
    size_axis(ax, ref)
    if logy:
        ax.set_yscale("log")
        ax.yaxis.set_major_formatter(PLAIN)
        ax.yaxis.set_minor_formatter(FuncFormatter(lambda v, _: ""))
    if ylim0:
        ax.set_ylim(bottom=0)
    ax.set_ylabel(ylabel)
    ax.set_title(title)
    ax.grid(True, which="major", alpha=0.8)
    ax.legend(title="Key size")
    fig.tight_layout()
    fig.savefig(out / fname)
    plt.close(fig)
    print(f"  {out / fname}")


def grouped_bars(groups, enc, enc_sd, dec, dec_sd, xlabel, title, fname, out):
    fig, ax = plt.subplots()
    x = range(len(groups))
    w = 0.38
    err = {"ecolor": "#52514e", "elinewidth": 1.2, "capsize": 4}
    for offset, vals, sds, color, name in ((-w / 2, enc, enc_sd, ENC_COLOR, "Encryption"),
                                           (w / 2, dec, dec_sd, DEC_COLOR, "Decryption")):
        ax.bar([i + offset for i in x], vals, w, yerr=sds, error_kw=err, color=color,
               edgecolor="white", linewidth=2, label=name)
        for i in x:   # label sits above the error bar so they never overlap
            ax.annotate(f"{vals[i]:.3g}", (i + offset, vals[i] + sds[i]), textcoords="offset points",
                        xytext=(0, 4), ha="center", fontsize=8, color="#52514e")
    ax.set_xticks(list(x), groups)
    ax.set_xlabel(xlabel)
    ax.set_ylabel("Mean time (ms), error bars = ±1 SD")
    ax.set_title(title)
    ax.set_ylim(0, max(e + s for e, s in zip(enc + dec, enc_sd + dec_sd)) * 1.15)
    ax.grid(True, axis="y", alpha=0.8)
    ax.set_axisbelow(True)
    ax.legend()
    fig.tight_layout()
    fig.savefig(out / fname)
    plt.close(fig)
    print(f"  {out / fname}")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--results", type=Path, default=ROOT / "results")
    ap.add_argument("--file-type", default="BIN")
    ap.add_argument("--compare-size", default=None, help="size label for Fig. 3 (default: largest)")
    ap.add_argument("--filetype-size", default="10MB", help="size label for Fig. 7")
    ap.add_argument("--filetype-key", type=int, default=256, help="key size for Fig. 7")
    args = ap.parse_args()

    summary = load(args.results / "aes_summary.csv")
    out = args.results / "graphs"
    out.mkdir(parents=True, exist_ok=True)
    ft = args.file_type
    keys = sorted({int(r["key_bits"]) for r in summary})
    if not any(r["file_type"] == ft for r in summary):
        sys.exit(f"No {ft} rows in the summary CSV.")
    n = int(summary[0]["trials"])
    print("Writing graphs:")

    line_plot(summary, ft, keys, "enc_mean_ms", "enc_std_ms", "Mean encryption time (ms, log scale)",
              f"Input Size vs Encryption Time - AES-GCM, {ft} data, n={n}", "fig1_enc_time.png", out)
    line_plot(summary, ft, keys, "dec_mean_ms", "dec_std_ms", "Mean decryption time (ms, log scale)",
              f"Input Size vs Decryption Time - AES-GCM, {ft} data, n={n}", "fig2_dec_time.png", out)

    sizes = [r["input_size"] for r in series(summary, ft, keys[0])]
    cmp_size = args.compare_size or sizes[-1]
    rows = [next(r for r in summary if r["file_type"] == ft and int(r["key_bits"]) == b
                 and r["input_size"] == cmp_size) for b in keys]
    grouped_bars([r["key_size"] for r in rows],
                 [r["enc_mean_ms"] for r in rows], [r["enc_std_ms"] for r in rows],
                 [r["dec_mean_ms"] for r in rows], [r["dec_std_ms"] for r in rows],
                 "AES key size (GCM mode)",
                 f"AES Key Size vs Time - {cmp_size} {ft} input, n={n}", "fig3_keysize_time.png", out)

    line_plot(summary, ft, keys, "enc_cpu_mean_pct", "enc_cpu_std_pct",
              "Mean process CPU during encryption (% of one core)",
              f"Input Size vs CPU Usage - AES-GCM encryption, {ft} data", "fig4_cpu.png", out,
              logy=False, ylim0=True)
    line_plot(summary, ft, keys, "enc_peak_mean_MB", None, "Mean peak traced memory (MB, log scale)",
              f"Input Size vs Memory Usage - AES-GCM encryption, {ft} data", "fig5_memory.png", out)
    line_plot(summary, ft, keys, "enc_throughput_MBps", None, "Encryption throughput (MB/s)",
              f"Input Size vs Throughput - AES-GCM encryption, {ft} data", "fig6_throughput.png", out,
              logy=False, ylim0=True)

    types = [t for t in ("TXT", "PDF", "JPG", "BIN") if any(
        r["file_type"] == t and int(r["key_bits"]) == args.filetype_key
        and r["input_size"] == args.filetype_size for r in summary)]
    if len(types) > 1:
        rows = [next(r for r in summary if r["file_type"] == t and int(r["key_bits"]) == args.filetype_key
                     and r["input_size"] == args.filetype_size) for t in types]
        grouped_bars(types, [r["enc_mean_ms"] for r in rows], [r["enc_std_ms"] for r in rows],
                     [r["dec_mean_ms"] for r in rows], [r["dec_std_ms"] for r in rows], "Input file type",
                     f"File Type vs Time - AES-{args.filetype_key}-GCM, {args.filetype_size}, n={n}",
                     "fig7_filetype.png", out)
    else:
        print("  (fig7 skipped: fewer than two file types at the chosen size/key)")


if __name__ == "__main__":
    main()
