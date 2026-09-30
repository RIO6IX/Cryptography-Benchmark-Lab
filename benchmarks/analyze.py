"""
Comparative analysis of the unified benchmark (IE3082 Cryptography - Member 4).

    python -m benchmarks.analyze                          # results/ -> tables, graphs, report values
    python -m benchmarks.analyze --results results/quick  # smoke-test output

Reads ONLY combined_summary.csv (+ environment_combined.txt for the environment
values) and writes, in the same results folder:
  comparative_table.csv     key metrics per algorithm/variant/operation at representative sizes,
                            with slowdown relative to the fastest operation at the same size
  stability_summary.csv     CV and relative 95 % CI of every configuration; CV > 10 % flagged
  hybrid_breakdown.csv      time per step of the hybrid scenario and each primitive's share
  report_values.csv         every {{PLACEHOLDER}} value used by the report draft, with its CSV source
  member4_report_filled.md  docs/member4_report_draft.md with the placeholders filled in
  graphs/cmp_*.png          comparison figures (300 dpi, readable in black and white):
    cmp_throughput_vs_size.png   throughput vs input size, log-log
    cmp_time_vs_size.png         time vs input size, one panel per algorithm, +/-1 SD
    cmp_cpu.png                  CPU utilisation per operation, +/-1 SD
    cmp_memory.png               peak traced memory vs input size, log-log
    cmp_small_payload.png        32 B / 190 B head-to-head, 95 % CI
    cmp_variance.png             mean +/- 95 % CI at one size, and CV per configuration
    cmp_hybrid_breakdown.png     share of each hybrid step (stacked), total time annotated
Missing data (e.g. no RSA rows before the RSA module exists) skips that part with a message.
"""
from __future__ import annotations

import argparse
import re
import statistics
import sys
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
from matplotlib.patches import Patch  # noqa: E402

from benchmarks.adapters.hybrid_adapter import RECEIVER_STEPS, SENDER_STEPS, STEP_PRIMITIVE  # noqa: E402
from benchmarks.framework import (HIGH_CV_PCT, HYBRID, KEYGEN, SIZE_SWEEP, SMALL_PAYLOAD,  # noqa: E402
                                  SUMMARY_FIELDS, check_schema, read_csv, write_csv)
from benchmarks.plot_results import PLAIN  # noqa: E402  (also applies the shared figure style)

ROOT = Path(__file__).resolve().parent.parent
SUMMARY_CSV = "combined_summary.csv"
ENV_TXT = "environment_combined.txt"
TEMPLATE = ROOT / "docs" / "member4_report_draft.md"
DPI = 300
INK, MUTED, GRID = "#0b0b0b", "#52514e", "#d9d8d3"

# Colour follows the entity (fixed order, never by rank); marker and hatch repeat the identity
# so every figure still reads in black and white. Palette validated for colour-vision deficiency.
ENTITY = {
    "AES-128": ("#2a78d6", "o", "///"),
    "AES-192": ("#eb6834", "s", "\\\\\\"),
    "AES-256": ("#1baf7a", "^", "xxx"),
    "SHA-256": ("#eda100", "D", "..."),
    "RSA-2048": ("#e87ba4", "v", "---"),
    "RSA-3072": ("#008300", "P", "+++"),
}
FALLBACK = ("#8a8984", "X", "ooo")
OP_LINE = {"encrypt": "-", "hash": "-", "keygen": "-", "decrypt": "--", "sign": "-.", "verify": ":"}
PRIMITIVE_COLOR = {"AES-GCM": ENTITY["AES-256"][0], "SHA-256": ENTITY["SHA-256"][0], "RSA": ENTITY["RSA-2048"][0]}
STEP_HATCH = {"sha256_digest": "", "aes_keygen": "...", "aes_encrypt": "", "rsa_wrap": "",
              "rsa_unwrap": "///", "aes_decrypt": "xxx", "sha256_verify": "///"}
PAYLOAD_SCENARIOS = (SMALL_PAYLOAD, SIZE_SWEEP)


def style(variant: str) -> tuple[str, str, str]:
    return ENTITY.get(variant, FALLBACK)


# --------------------------------------------------------------- loading / selection
def load(results: Path) -> list[dict]:
    path = results / SUMMARY_CSV
    if not path.exists():
        sys.exit(f"{path} not found - run: python -m benchmarks.benchmark_all")
    check_schema(path, SUMMARY_FIELDS)
    return read_csv(path)


def load_environment(results: Path) -> dict[str, str]:
    env = {}
    path = results / ENV_TXT
    if path.exists():
        for line in path.read_text(encoding="utf-8").splitlines():
            if ": " in line:
                k, v = line.split(": ", 1)
                env[k] = v
    return env


def pick(rows, **where) -> list[dict]:
    return [r for r in rows if all(r.get(k) == v for k, v in where.items())]


def one(rows, **where) -> dict | None:
    found = pick(rows, **where)
    return found[0] if found else None


def size_series(rows, variant: str, op: str, ftype: str) -> list[dict]:
    """One operation across all payload sizes (small payloads + size sweep) for one file type."""
    found = [r for r in rows if r["variant"] == variant and r["operation"] == op
             and r["scenario"] in PAYLOAD_SCENARIOS and r["file_type"] == ftype]
    return sorted(found, key=lambda r: r["size_bytes"])


def sweep_sizes(rows, ftype: str) -> list[str]:
    found = {r["size_label"]: r["size_bytes"] for r in rows if r["scenario"] == SIZE_SWEEP and r["file_type"] == ftype}
    return sorted(found, key=found.get)


def small_sizes(rows) -> list[str]:
    found = {r["size_label"]: r["size_bytes"] for r in rows if r["scenario"] == SMALL_PAYLOAD}
    return sorted(found, key=found.get)


def rep_size(rows, ftype: str, wanted: str) -> str | None:
    sizes = sweep_sizes(rows, ftype)
    return wanted if wanted in sizes else (sizes[-1] if sizes else None)


def variants_of(rows, algorithm: str) -> list[str]:
    return sorted({r["variant"] for r in rows if r["algorithm"] == algorithm},
                  key=lambda v: (len(v), v))


def config_name(r: dict) -> str:
    size = f" {r['file_type']} {r['size_label']}" if r["size_label"] else ""
    return f"{r['scenario']}: {r['variant']} {r['operation']}{size}"


# --------------------------------------------------------------- tables
def comparative_table(rows, ftype: str, sizes: list[str]) -> list[dict]:
    chosen = [r for r in rows if r["scenario"] in (SMALL_PAYLOAD, KEYGEN)]
    chosen += [r for r in rows if r["scenario"] == SIZE_SWEEP and r["file_type"] == ftype and r["size_label"] in sizes]
    out = []
    for r in chosen:
        peers = pick(chosen, scenario=r["scenario"], size_label=r["size_label"])
        fastest = min(p["mean_ms"] for p in peers)
        out.append({"scenario": r["scenario"], "algorithm": r["algorithm"], "variant": r["variant"],
                    "operation": r["operation"], "file_type": r["file_type"], "size_label": r["size_label"],
                    "size_bytes": int(r["size_bytes"]), "trials": int(r["trials"]), "mean_ms": r["mean_ms"],
                    "ci95": r["ci95"], "sd_ms": r["sd_ms"], "cv": r["cv"], "throughput_mbps": r["throughput_mbps"],
                    "cpu_pct_mean": r["cpu_pct_mean"], "peak_mem_mb": r["peak_mem_mb"],
                    "x_vs_fastest": r["mean_ms"] / fastest, "correctness": r["correctness"],
                    "source": f"{SUMMARY_CSV}: {config_name(r)}"})
    order = {KEYGEN: 0, SMALL_PAYLOAD: 1, SIZE_SWEEP: 2}
    return sorted(out, key=lambda r: (order[r["scenario"]], r["size_bytes"], r["mean_ms"]))


COMPARATIVE_FIELDS = ["scenario", "algorithm", "variant", "operation", "file_type", "size_label", "size_bytes",
                      "trials", "mean_ms", "ci95", "sd_ms", "cv", "throughput_mbps", "cpu_pct_mean",
                      "peak_mem_mb", "x_vs_fastest", "correctness", "source"]
STABILITY_FIELDS = ["scenario", "algorithm", "variant", "operation", "file_type", "size_label", "size_bytes",
                    "trials", "mean_ms", "sd_ms", "cv", "ci95", "ci95_pct_of_mean", "flag"]
HYBRID_FIELDS = ["variant", "file_type", "size_label", "size_bytes", "trials", *SENDER_STEPS, *RECEIVER_STEPS,
                 "sender_total_ms", "receiver_total_ms", "total_ms", "rsa_share_pct", "aes_share_pct",
                 "sha_share_pct", "aes256_only_ms", "overhead_vs_aes_only_pct"]


def stability(rows) -> list[dict]:
    out = []
    for r in rows:
        out.append({k: r[k] for k in ("scenario", "algorithm", "variant", "operation", "file_type", "size_label",
                                      "size_bytes", "trials", "mean_ms", "sd_ms", "cv", "ci95")}
                   | {"ci95_pct_of_mean": r["ci95"] / r["mean_ms"] * 100 if r["mean_ms"] else 0.0,
                      "flag": f"CV>{HIGH_CV_PCT:g}%" if r["cv"] > HIGH_CV_PCT else "ok"})
    return sorted(out, key=lambda r: -r["cv"])


def hybrid_breakdown(rows) -> list[dict]:
    out = []
    hyb = pick(rows, scenario=HYBRID)
    for variant in sorted({r["variant"] for r in hyb}):
        for label in sorted({r["size_label"] for r in pick(hyb, variant=variant)},
                            key=lambda s: one(hyb, variant=variant, size_label=s)["size_bytes"]):
            steps = {r["operation"]: r for r in pick(hyb, variant=variant, size_label=label)}
            if not all(s in steps for s in SENDER_STEPS + RECEIVER_STEPS):
                continue
            ms = {s: steps[s]["mean_ms"] for s in SENDER_STEPS + RECEIVER_STEPS}
            total = sum(ms.values())
            share = {p: sum(v for s, v in ms.items() if STEP_PRIMITIVE[s] == p) / total * 100
                     for p in ("RSA", "AES-GCM", "SHA-256")}
            first = next(iter(steps.values()))
            aes_rows = [one(rows, scenario=SIZE_SWEEP, variant="AES-256", operation=op,
                            file_type=first["file_type"], size_label=label) for op in ("encrypt", "decrypt")]
            aes_only = sum(r["mean_ms"] for r in aes_rows) if all(aes_rows) else None
            out.append({"variant": variant, "file_type": first["file_type"], "size_label": label,
                        "size_bytes": int(first["size_bytes"]), "trials": int(first["trials"]), **ms,
                        "sender_total_ms": sum(ms[s] for s in SENDER_STEPS),
                        "receiver_total_ms": sum(ms[s] for s in RECEIVER_STEPS), "total_ms": total,
                        "rsa_share_pct": share["RSA"], "aes_share_pct": share["AES-GCM"],
                        "sha_share_pct": share["SHA-256"], "aes256_only_ms": aes_only,
                        "overhead_vs_aes_only_pct": (total - aes_only) / aes_only * 100 if aes_only else None})
    return out


# --------------------------------------------------------------- report values
def fmt(v: float | None) -> str | None:
    if v is None:
        return None
    a = abs(v)
    if a >= 100:
        return f"{v:,.0f}"
    if a >= 10:
        return f"{v:.1f}"
    return f"{v:.3g}"


def token(variant: str) -> str:
    if "+" in variant:                                   # hybrid "RSA-2048+AES-256" -> HYB_RSA2048
        return "HYB_" + re.sub(r"[^A-Z0-9]", "", variant.split("+")[0].upper())
    return re.sub(r"[^A-Z0-9]", "", variant.upper())


def row_key(r: dict) -> str:
    ft = r["file_type"] if r["file_type"] not in ("", "BIN") else ""
    return "_".join(p for p in (token(r["variant"]), r["operation"].upper(), ft, r["size_label"]) if p)


METRICS = {"MS": "mean_ms", "SD": "sd_ms", "CV": "cv", "CI95": "ci95", "MBPS": "throughput_mbps",
           "CPU": "cpu_pct_mean", "MEM": "peak_mem_mb"}


def report_values(rows, hybrid: list[dict], stab: list[dict], env: dict[str, str]) -> list[dict]:
    vals: list[dict] = []

    def add(key, value, source):
        if value is not None:
            vals.append({"key": key, "value": value if isinstance(value, str) else fmt(value), "source": source})

    for r in rows:
        for m, col in METRICS.items():
            add(f"{row_key(r)}_{m}", r[col], f"{SUMMARY_CSV}: {config_name(r)} -> {col}")
        add(f"{row_key(r)}_CORRECT", r["correctness"], f"{SUMMARY_CSV}: {config_name(r)} -> correctness")

    def mean_of(**w):
        r = one(rows, **w)
        return r["mean_ms"] if r else None

    # size sweep: SHA-256 vs AES-256, AES key-size spread, file-type spread
    for label in sweep_sizes(rows, "BIN"):
        sha = one(rows, scenario=SIZE_SWEEP, variant="SHA-256", operation="hash", file_type="BIN", size_label=label)
        aes = one(rows, scenario=SIZE_SWEEP, variant="AES-256", operation="encrypt", file_type="BIN", size_label=label)
        src = f"{SUMMARY_CSV}: size_sweep BIN {label}"
        if sha and aes and sha["throughput_mbps"] and aes["throughput_mbps"]:
            add(f"SHA256_VS_AES256_{label}_X", sha["throughput_mbps"] / aes["throughput_mbps"],
                f"{src}, throughput_mbps SHA-256 hash / AES-256 encrypt")
        for op in ("encrypt", "decrypt"):
            means = [m for m in (mean_of(scenario=SIZE_SWEEP, variant=v, operation=op, file_type="BIN",
                                         size_label=label) for v in ("AES-128", "AES-192", "AES-256")) if m]
            if len(means) == 3:
                add(f"AES_KEYSIZE_SPREAD_{op.upper()}_{label}_PCT", (max(means) - min(means)) / min(means) * 100,
                    f"{src}, (max - min) / min of AES-128/192/256 {op} mean_ms")
        a128 = mean_of(scenario=SIZE_SWEEP, variant="AES-128", operation="encrypt", file_type="BIN", size_label=label)
        a256 = aes["mean_ms"] if aes else None
        if a128 and a256:
            add(f"AES256_VS_AES128_{label}_PCT", (a256 - a128) / a128 * 100,
                f"{src}, (AES-256 - AES-128) / AES-128 encrypt mean_ms")
        for variant, op in (("AES-256", "encrypt"), ("SHA-256", "hash")):
            by_type = [r["mean_ms"] for r in pick(rows, scenario=SIZE_SWEEP, variant=variant, operation=op,
                                                   size_label=label)]
            if len(by_type) > 1:
                add(f"{token(variant)}_FILETYPE_SPREAD_{label}_PCT", (max(by_type) - min(by_type)) / min(by_type) * 100,
                    f"{SUMMARY_CSV}: size_sweep {variant} {op} {label}, (max - min) / min over file types")

    # small payloads: RSA vs AES-256 / SHA-256, RSA-3072 vs RSA-2048
    for label in small_sizes(rows):
        src = f"{SUMMARY_CSV}: small_payload {label}"
        aes_enc = mean_of(scenario=SMALL_PAYLOAD, variant="AES-256", operation="encrypt", size_label=label)
        aes_dec = mean_of(scenario=SMALL_PAYLOAD, variant="AES-256", operation="decrypt", size_label=label)
        sha = mean_of(scenario=SMALL_PAYLOAD, variant="SHA-256", operation="hash", size_label=label)
        for v in variants_of(rows, "RSA"):
            t = token(v)
            for op, ref, name, ref_name in (("encrypt", aes_enc, "AES256", "AES-256 encrypt"),
                                            ("decrypt", aes_dec, "AES256", "AES-256 decrypt"),
                                            ("sign", sha, "SHA256", "SHA-256 hash")):
                m = mean_of(scenario=SMALL_PAYLOAD, variant=v, operation=op, size_label=label)
                if m and ref:
                    add(f"{t}_{op.upper()}_VS_{name}_{label}_X", m / ref, f"{src}, mean_ms {v} {op} / {ref_name}")
        for op in ("encrypt", "decrypt", "sign", "verify"):
            a, b = (mean_of(scenario=SMALL_PAYLOAD, variant=v, operation=op, size_label=label)
                    for v in ("RSA-3072", "RSA-2048"))
            if a and b:
                add(f"RSA3072_VS_RSA2048_{op.upper()}_{label}_X", a / b, f"{src}, mean_ms RSA-3072 / RSA-2048 {op}")
    k3, k2 = (mean_of(scenario=KEYGEN, variant=v, operation="keygen") for v in ("RSA-3072", "RSA-2048"))
    if k3 and k2:
        add("RSA3072_VS_RSA2048_KEYGEN_X", k3 / k2, f"{SUMMARY_CSV}: keygen, mean_ms RSA-3072 / RSA-2048")

    for h in hybrid:
        base = f"{token(h['variant'])}_{h['size_label']}"
        src = f"hybrid_breakdown.csv: {h['variant']} {h['file_type']} {h['size_label']}"
        for col, name in (("total_ms", "TOTAL_MS"), ("sender_total_ms", "SENDER_MS"),
                          ("receiver_total_ms", "RECEIVER_MS"), ("rsa_share_pct", "RSA_SHARE_PCT"),
                          ("aes_share_pct", "AES_SHARE_PCT"), ("sha_share_pct", "SHA_SHARE_PCT"),
                          ("overhead_vs_aes_only_pct", "OVERHEAD_VS_AES_PCT")):
            add(f"{base}_{name}", h[col], f"{src} -> {col}")

    cvs = [s["cv"] for s in stab]
    if cvs:
        high = [s for s in stab if s["flag"] != "ok"]
        worst = stab[0]
        large = [r["cv"] for r in rows if r["size_bytes"] >= 1024**2]
        small = [r["cv"] for r in rows if 0 < r["size_bytes"] < 1024**2]
        add("N_CONFIGS", str(len(cvs)), f"{SUMMARY_CSV}: number of rows")
        add("N_HIGH_CV", str(len(high)), f"stability_summary.csv: rows with CV > {HIGH_CV_PCT:g} %")
        add("PCT_HIGH_CV", len(high) / len(cvs) * 100, "stability_summary.csv: share of rows flagged")
        add("MAX_CV_PCT", worst["cv"], "stability_summary.csv: first row (sorted by CV)")
        add("MAX_CV_CONFIG", f"{worst['variant']} {worst['operation']} {worst['file_type']} {worst['size_label']}".strip(),
            "stability_summary.csv: first row")
        add("MEDIAN_CV_PCT", statistics.median(cvs), "stability_summary.csv: median of cv")
        if large:
            add("MEDIAN_CV_LARGE_PCT", statistics.median(large), f"{SUMMARY_CSV}: median cv, size >= 1 MB")
        if small:
            add("MEDIAN_CV_SMALL_PCT", statistics.median(small), f"{SUMMARY_CSV}: median cv, 0 < size < 1 MB")
        fails = [r for r in rows if not r["correctness"].startswith("PASS")]
        add("CORRECTNESS_SUMMARY", "all configurations PASS" if not fails else f"{len(fails)} configurations FAIL",
            f"{SUMMARY_CSV}: correctness column")
        add("TRIALS", str(int(max(r["trials"] for r in rows))), f"{SUMMARY_CSV}: trials")

    for key, env_key in (("ENV_CPU", "CPU"), ("ENV_LOGICAL", "Logical processors"), ("ENV_RAM_GB", "RAM (GB)"),
                         ("ENV_OS", "OS"), ("ENV_PYTHON", "Python"), ("ENV_CRYPTOGRAPHY", "cryptography"),
                         ("ENV_OPENSSL", "OpenSSL"), ("ENV_HASHLIB", "hashlib backend"), ("ENV_POWER", "Power"),
                         ("ENV_CPU_METHOD", "CPU measurement"), ("WARMUP", "Warm-up runs discarded per configuration"),
                         ("CPU_WINDOW_S", "CPU sampling window (s)"), ("RUN_STARTED", "Started"),
                         ("RUN_DURATION_S", "Benchmark duration (s)"), ("RSA_STATUS", "RSA module"),
                         ("RUN_TYPE", "Run type")):
        if env_key in env:
            add(key, env[env_key], f"{ENV_TXT}: {env_key}")
    return vals


PLACEHOLDER = re.compile(r"\{\{([A-Z0-9_]+)\}\}")


def fill_template(text: str, values: dict[str, str]) -> tuple[str, list[str]]:
    """Replace {{KEY}} with its value; unknown keys become a visible **[missing: KEY]** marker."""
    missing = []

    def sub(m):
        if m.group(1) in values:
            return values[m.group(1)]
        missing.append(m.group(1))
        return f"**[missing: {m.group(1)}]**"
    return PLACEHOLDER.sub(sub, text), sorted(set(missing))


# --------------------------------------------------------------- figures
def save(fig, out: Path, name: str):
    fig.tight_layout()
    fig.savefig(out / name, dpi=DPI)
    plt.close(fig)
    print(f"  {out / name}")


def size_axis(ax, series_rows: list[dict]):
    ticks = {r["size_bytes"]: r["size_label"] for r in series_rows}
    ax.set_xscale("log")
    ax.set_xticks(sorted(ticks), [ticks[s] for s in sorted(ticks)])
    ax.minorticks_off()
    ax.set_xlabel("Input size (log scale; 1 KB = 1024 B, 1 MB = 1,048,576 B)")
    for lbl in ax.get_xticklabels():          # neighbouring sizes (190B/300B, 5MB/10MB) sit close on a log axis
        lbl.set_rotation(40)
        lbl.set_horizontalalignment("right")


def log_y(ax):
    ax.set_yscale("log")
    ax.yaxis.set_major_formatter(PLAIN)


def plot_series(ax, rows, variant, op, y, err=None, label=None):
    s = rows
    color, marker, _ = style(variant)
    hollow = op in ("decrypt", "verify")
    ax.errorbar([r["size_bytes"] for r in s], [r[y] for r in s], yerr=[r[err] for r in s] if err else None,
                color=color, marker=marker, markersize=6.5, linestyle=OP_LINE.get(op, "-"), linewidth=2,
                capsize=3, markerfacecolor="white" if hollow else color, markeredgewidth=1.5,
                label=label or f"{variant} {op}")


def line_series(rows, ftype: str) -> list[tuple[str, str, list[dict]]]:
    """Series shown in the size figures: AES encrypt per key size, AES-256 decrypt, SHA-256, RSA encrypt."""
    wanted = [("AES-128", "encrypt"), ("AES-192", "encrypt"), ("AES-256", "encrypt"), ("AES-256", "decrypt"),
              ("SHA-256", "hash")] + [(v, "encrypt") for v in variants_of(rows, "RSA")]
    out = []
    for v, op in wanted:
        s = [r for r in size_series(rows, v, op, ftype) if r["throughput_mbps"]]
        if s:
            out.append((v, op, s))
    return out


def fig_throughput(rows, ftype, out, n):
    series = line_series(rows, ftype)
    if not series:
        print("  (cmp_throughput_vs_size skipped: no payload rows)")
        return
    fig, ax = plt.subplots(figsize=(7.2, 4.5))
    for v, op, s in series:
        plot_series(ax, s, v, op, "throughput_mbps")
    size_axis(ax, [r for _, _, s in series for r in s])
    log_y(ax)
    ax.set_ylabel("Throughput (MB/s, log scale)")
    ax.set_title(f"Input Size vs Throughput - all algorithms, {ftype} data, n={n}")
    ax.grid(True, which="major", alpha=0.8)
    ax.legend(fontsize=8, ncol=2, loc="upper left")
    save(fig, out, "cmp_throughput_vs_size.png")


def fig_time_panels(rows, ftype, out, n):
    panels = []
    aes = [(v, op, size_series(rows, v, op, ftype)) for v in variants_of(rows, "AES-GCM") for op in ("encrypt", "decrypt")]
    if any(s for *_, s in aes):
        panels.append(("AES-GCM", aes))
    sha = [("SHA-256", "hash", size_series(rows, "SHA-256", "hash", ftype))]
    if sha[0][2]:
        panels.append(("SHA-256", sha))
    rsa = [(v, op, size_series(rows, v, op, ftype)) for v in variants_of(rows, "RSA")
           for op in ("encrypt", "decrypt", "sign", "verify")]
    if any(s for *_, s in rsa):
        panels.append(("RSA (payloads within the OAEP limit)", rsa))
    if not panels:
        print("  (cmp_time_vs_size skipped: no payload rows)")
        return
    fig, axes = plt.subplots(1, len(panels), figsize=(4.6 * len(panels), 6.2), squeeze=False)
    for ax, (title, series) in zip(axes[0], panels):
        all_rows = []
        for v, op, s in series:
            if s:
                plot_series(ax, s, v, op, "mean_ms", "sd_ms")
                all_rows += s
        size_axis(ax, all_rows)
        ax.set_xlabel("Input size (log scale)")
        log_y(ax)
        ax.set_ylabel("Mean time (ms, log scale), ±1 SD")
        ax.set_title(title)
        ax.grid(True, which="major", alpha=0.8)
        ax.legend(fontsize=7.5, loc="upper center", bbox_to_anchor=(0.5, -0.24), ncol=2)
    fig.suptitle(f"Input Size vs Time per Algorithm - {ftype} data, n={n}", fontweight="bold", fontsize=11)
    save(fig, out, "cmp_time_vs_size.png")


def hbar_rows(rows, ftype, rep: str | None) -> list[dict]:
    """One row per (variant, op): size-sweep ops at the representative size, RSA at its largest small size, keygen."""
    chosen = []
    if rep:
        chosen += [r for r in rows if r["scenario"] == SIZE_SWEEP and r["file_type"] == ftype and r["size_label"] == rep]
    smalls = small_sizes(rows)
    for v in variants_of(rows, "RSA"):
        for op in ("encrypt", "decrypt", "sign", "verify"):
            found = [r for r in pick(rows, scenario=SMALL_PAYLOAD, variant=v, operation=op)]
            if found:
                chosen.append(max(found, key=lambda r: r["size_bytes"]))
        k = one(rows, scenario=KEYGEN, variant=v, operation="keygen")
        if k:
            chosen.append(k)
    if not chosen and smalls:
        chosen = pick(rows, scenario=SMALL_PAYLOAD, size_label=smalls[-1])
    return chosen


def hbar(ax, chosen, value, err, xlabel, label_fmt=fmt):
    labels = [f"{r['variant']} {r['operation']}" + (f" ({r['size_label']})" if r["size_label"] else "")
              for r in chosen]
    ys = range(len(chosen))
    for y, r in zip(ys, chosen):
        color, _, hatch = style(r["variant"])
        ax.barh(y, r[value], xerr=r[err] if err else None, color=color, hatch=hatch, edgecolor="white",
                linewidth=2, height=0.7, error_kw={"ecolor": MUTED, "elinewidth": 1.2, "capsize": 3})
        ax.annotate(label_fmt(r[value]), (r[value] + (r[err] if err else 0), y), textcoords="offset points",
                    xytext=(4, 0), va="center", fontsize=7.5, color=MUTED)
    ax.set_yticks(list(ys), labels, fontsize=8)
    ax.invert_yaxis()
    ax.set_xlabel(xlabel)
    ax.grid(True, axis="x", alpha=0.8)
    ax.set_axisbelow(True)


def fig_cpu(rows, ftype, rep, out, n):
    chosen = hbar_rows(rows, ftype, rep)
    if not chosen:
        print("  (cmp_cpu skipped: no rows)")
        return
    fig, ax = plt.subplots(figsize=(7.2, 0.32 * len(chosen) + 1.6))
    hbar(ax, chosen, "cpu_pct_mean", "cpu_pct_sd", "Mean process CPU (% of one logical core), ±1 SD",
         label_fmt=lambda v: f"{v:.1f}")
    ax.axvline(100, color=MUTED, linestyle="--", linewidth=1)
    ax.set_xlim(0, max(115, max(r["cpu_pct_mean"] + r["cpu_pct_sd"] for r in chosen) * 1.12))
    ax.set_title(f"CPU Utilisation per Operation ({ftype} data), n={n}")
    save(fig, out, "cmp_cpu.png")


def fig_memory(rows, ftype, out, n):
    series = [(v, op, size_series(rows, v, op, ftype)) for v, op, _ in line_series(rows, ftype)]
    series = [x for x in series if x[2]]
    if not series:
        print("  (cmp_memory skipped: no payload rows)")
        return
    fig, ax = plt.subplots(figsize=(7.2, 4.5))
    for v, op, s in series:
        plot_series(ax, s, v, op, "peak_mem_mb")
    size_axis(ax, [r for _, _, s in series for r in s])
    log_y(ax)
    ax.set_ylabel("Mean peak traced memory (MB, log scale)")
    ax.set_title(f"Input Size vs Peak Memory (tracemalloc) - {ftype} data, n={n}")
    ax.grid(True, which="major", alpha=0.8)
    ax.legend(fontsize=8, ncol=2, loc="upper left")
    save(fig, out, "cmp_memory.png")


def fig_small_payload(rows, out, n):
    sizes = small_sizes(rows)
    small = pick(rows, scenario=SMALL_PAYLOAD)
    if not small:
        print("  (cmp_small_payload skipped: no small-payload rows)")
        return
    cats = []
    for r in small:
        c = (r["variant"], r["operation"])
        if c not in cats:
            cats.append(c)
    order = {v: i for i, v in enumerate(ENTITY)}
    cats.sort(key=lambda c: (order.get(c[0], 99), list(OP_LINE).index(c[1]) if c[1] in OP_LINE else 9))
    width = 0.8 / len(sizes)
    size_hatch = ["", "///", "xxx", "..."]
    fig, ax = plt.subplots(figsize=(max(7.2, 0.62 * len(cats) + 2), 4.6))
    for j, label in enumerate(sizes):
        for i, (v, op) in enumerate(cats):
            r = one(small, variant=v, operation=op, size_label=label)
            if not r:
                continue
            x = i - 0.4 + width * (j + 0.5)
            ax.bar(x, r["mean_ms"] * 1000, width, yerr=r["ci95"] * 1000, color=style(v)[0],
                   hatch=size_hatch[j % len(size_hatch)], edgecolor="white", linewidth=2,
                   error_kw={"ecolor": MUTED, "elinewidth": 1.1, "capsize": 2})
    ax.set_xticks(range(len(cats)), [f"{v}\n{op}" for v, op in cats], fontsize=8)
    log_y(ax)
    ax.set_ylabel("Mean time (µs, log scale), error bars = 95 % CI")
    ax.set_title(f"Small-Payload Head-to-Head - same bytes for every algorithm, n={n}")
    ax.grid(True, axis="y", alpha=0.8)
    ax.set_axisbelow(True)
    handles = [Patch(facecolor="#8a8984", hatch=size_hatch[j % len(size_hatch)], edgecolor="white",
                     label=f"{label} payload") for j, label in enumerate(sizes)]
    ax.legend(handles=handles, loc="upper left", fontsize=8)
    save(fig, out, "cmp_small_payload.png")


def fig_variance(rows, ftype, rep, out, n):
    series = [(v, op, size_series(rows, v, op, ftype)) for v, op, _ in line_series(rows, ftype)]
    series = [x for x in series if x[2]]
    at_rep = [r for r in rows if r["scenario"] == SIZE_SWEEP and r["file_type"] == ftype and r["size_label"] == rep]
    if not series:
        print("  (cmp_variance skipped: no payload rows)")
        return
    fig, (a1, a2) = plt.subplots(1, 2, figsize=(10, 4.6))
    if at_rep:
        hbar(a1, at_rep, "mean_ms", "ci95", f"Mean time (ms), error bars = 95 % CI")
        a1.set_xlim(left=0)
        a1.set_title(f"Mean ± 95 % CI at {rep}")
    else:
        a1.set_axis_off()
    for v, op, s in series:
        plot_series(a2, s, v, op, "cv")
    a2.axhline(HIGH_CV_PCT, color=MUTED, linestyle="--", linewidth=1)
    a2.annotate(f"{HIGH_CV_PCT:g} % stability threshold", (0.99, HIGH_CV_PCT), xycoords=("axes fraction", "data"),
                textcoords="offset points", xytext=(0, 4), ha="right", fontsize=8, color=MUTED)
    size_axis(a2, [r for _, _, s in series for r in s])
    a2.set_xlabel("Input size (log scale)")
    a2.set_ylim(bottom=0)
    a2.set_ylabel("Coefficient of variation (%)")
    a2.set_title("Run-to-run variation vs input size")
    a2.grid(True, which="major", alpha=0.8)
    a2.legend(fontsize=7.5, loc="upper right")
    fig.suptitle(f"Measurement Stability - {ftype} data, n={n}", fontweight="bold", fontsize=11)
    save(fig, out, "cmp_variance.png")


def fig_hybrid(hybrid: list[dict], out):
    if not hybrid:
        print("  (cmp_hybrid_breakdown skipped: no hybrid rows - needs the RSA module)")
        return
    steps = list(SENDER_STEPS + RECEIVER_STEPS)
    labels = [f"{h['variant'].split('+')[0]}\n{h['size_label']}" for h in hybrid]
    fig, ax = plt.subplots(figsize=(max(7.2, 1.1 * len(hybrid) + 3.5), 4.8))
    bottom = [0.0] * len(hybrid)
    for s in steps:
        shares = [h[s] / h["total_ms"] * 100 for h in hybrid]
        ax.bar(range(len(hybrid)), shares, 0.62, bottom=bottom, color=PRIMITIVE_COLOR[STEP_PRIMITIVE[s]],
               hatch=STEP_HATCH[s], edgecolor="white", linewidth=2, label=s.replace("_", " "))
        bottom = [b + v for b, v in zip(bottom, shares)]
    for i, h in enumerate(hybrid):
        ax.annotate(f"total {fmt(h['total_ms'])} ms", (i, 100), textcoords="offset points", xytext=(0, 4),
                    ha="center", fontsize=8, color=MUTED)
    ax.set_xticks(range(len(hybrid)), labels, fontsize=8.5)
    ax.set_ylim(0, 112)
    ax.set_ylabel("Share of end-to-end time (%)")
    ax.set_xlabel("RSA key size (AES-256-GCM + SHA-256) and file size")
    ax.set_title(f"Hybrid Encryption - where the time goes, n={int(hybrid[0]['trials'])}")
    ax.grid(True, axis="y", alpha=0.8)
    ax.set_axisbelow(True)
    ax.legend(loc="center left", bbox_to_anchor=(1.0, 0.5), fontsize=8, title="Step (sender, then receiver)")
    save(fig, out, "cmp_hybrid_breakdown.png")


# --------------------------------------------------------------- main
def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--results", type=Path, default=ROOT / "results")
    ap.add_argument("--file-type", default="BIN", help="file type used in the size figures")
    ap.add_argument("--rep-size", default="10MB", help="size used in the CPU and CI figures (default: 10MB or largest)")
    ap.add_argument("--table-sizes", nargs="+", default=["1KB", "1MB", "10MB", "50MB"],
                    help="size-sweep sizes included in comparative_table.csv")
    ap.add_argument("--template", type=Path, default=TEMPLATE, help="report draft with {{PLACEHOLDERS}}")
    args = ap.parse_args(argv)

    res = args.results.resolve()
    rows = load(res)
    if not rows:
        sys.exit(f"{res / SUMMARY_CSV} has no rows.")
    env = load_environment(res)
    ft = args.file_type
    n = int(max(r["trials"] for r in rows))
    rep = rep_size(rows, ft, args.rep_size)

    print("Writing tables:")
    table = comparative_table(rows, ft, args.table_sizes)
    stab = stability(rows)
    hyb = hybrid_breakdown(rows)
    for name, fields, data in (("comparative_table.csv", COMPARATIVE_FIELDS, table),
                               ("stability_summary.csv", STABILITY_FIELDS, stab),
                               ("hybrid_breakdown.csv", HYBRID_FIELDS, hyb)):
        if data or name != "hybrid_breakdown.csv":
            write_csv(res / name, fields, data)
            print(f"  {res / name}")
        else:
            print("  (hybrid_breakdown.csv skipped: no hybrid rows - needs the RSA module)")

    high = [s for s in stab if s["flag"] != "ok"]
    print(f"\nStability: {len(high)} of {len(stab)} configurations have CV > {HIGH_CV_PCT:g} %")
    for s in high[:10]:
        print(f"  CV {s['cv']:6.1f}%  {s['scenario']:<13} {s['variant']:<17} {s['operation']:<13} "
              f"{s['file_type'] or '-':<4} {s['size_label'] or '-'}")
    if len(high) > 10:
        print(f"  ... {len(high) - 10} more in stability_summary.csv")

    out = res / "graphs"
    out.mkdir(parents=True, exist_ok=True)
    print("\nWriting graphs:")
    fig_throughput(rows, ft, out, n)
    fig_time_panels(rows, ft, out, n)
    fig_cpu(rows, ft, rep, out, n)
    fig_memory(rows, ft, out, n)
    fig_small_payload(rows, out, n)
    fig_variance(rows, ft, rep, out, n)
    fig_hybrid(hyb, out)

    values = report_values(rows, hyb, stab, env)
    write_csv(res / "report_values.csv", ["key", "value", "source"], values)
    print(f"\nReport values: {len(values)} -> {res / 'report_values.csv'}")
    if args.template.exists():
        text, missing = fill_template(args.template.read_text(encoding="utf-8"),
                                      {v["key"]: v["value"] for v in values})
        (res / "member4_report_filled.md").write_text(text, encoding="utf-8")
        print(f"Filled report draft -> {res / 'member4_report_filled.md'}")
        if missing:
            print(f"  {len(missing)} placeholder(s) have no data in this run (marked **[missing: ...]**): "
                  f"{', '.join(missing[:12])}{' ...' if len(missing) > 12 else ''}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
