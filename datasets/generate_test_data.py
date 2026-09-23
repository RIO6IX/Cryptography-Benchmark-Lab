"""
Generate reproducible AES test datasets.

    python -m datasets.generate_test_data            # all types and sizes
    python -m datasets.generate_test_data --types BIN

Output: datasets/data/<TYPE>/<size>.<ext> and datasets/manifest.csv (SHA-256 of
every file, so anyone can confirm they benchmarked identical inputs).

Data types
  BIN  pseudorandom bytes from SHAKE-256 with a fixed seed: incompressible,
       deterministic, and not produced by Python's `random` module.
  TXT  repeated English/ASCII text (highly redundant content).
  PDF  bytes of a PDF document repeated/truncated to the target size.
  JPG  bytes of a JPEG image repeated/truncated to the target size.

For PDF and JPG, a real file placed at datasets/samples/sample.pdf or
datasets/samples/sample.jpg is used if present; otherwise a deterministic sample
is drawn with matplotlib. Truncated files are no longer valid PDFs/JPEGs, which
does not matter here: AES-GCM treats all input as an opaque byte string.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import io
from pathlib import Path

ROOT = Path(__file__).resolve().parent
DATA_DIR = ROOT / "data"
SAMPLES_DIR = ROOT / "samples"
MANIFEST = ROOT / "manifest.csv"

SIZES = {"1KB": 1024, "100KB": 100 * 1024, "1MB": 1024**2,
         "5MB": 5 * 1024**2, "10MB": 10 * 1024**2, "50MB": 50 * 1024**2}
FILE_TYPES = {"BIN": "bin", "TXT": "txt", "PDF": "pdf", "JPG": "jpg"}
SEED = b"IE3082-AES-IT23777590"


def dataset_path(ftype: str, label: str) -> Path:
    return DATA_DIR / ftype / f"{label}.{FILE_TYPES[ftype]}"


def _fit(unit: bytes, size: int) -> bytes:
    """Repeat or truncate `unit` to exactly `size` bytes."""
    return (unit * (size // len(unit) + 1))[:size]


def _sample_figure():
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    import numpy as np
    x = np.linspace(0, 8 * np.pi, 600)
    img = np.sin(x[:, None]) * np.cos(x[None, :] * 0.7) + np.sin(x[:, None] * x[None, :] / 40)
    fig, ax = plt.subplots(figsize=(6, 6))
    ax.imshow(img, cmap="viridis")
    ax.set_title("IE3082 AES test sample")
    ax.text(10, 60, "Deterministic sample for AES-GCM benchmarking", color="white")
    return fig, plt


def _sample_bytes(ftype: str) -> tuple[bytes, str]:
    real = SAMPLES_DIR / f"sample.{FILE_TYPES[ftype]}"
    if real.exists():
        return real.read_bytes(), f"real file {real.name}"
    fig, plt = _sample_figure()
    buf = io.BytesIO()
    if ftype == "PDF":
        fig.savefig(buf, format="pdf", metadata={"CreationDate": None, "Creator": None, "Producer": None})
    else:
        fig.savefig(buf, format="jpg", dpi=150, pil_kwargs={"quality": 90})
    plt.close(fig)
    return buf.getvalue(), "generated with matplotlib"


def make_bytes(ftype: str, size: int, cache: dict) -> bytes:
    if ftype == "BIN":
        return hashlib.shake_256(SEED + size.to_bytes(8, "big")).digest(size)
    if ftype == "TXT":
        text = (b"The quick brown fox jumps over the lazy dog. "
                b"AES-GCM provides confidentiality and integrity for this text.\n")
        return _fit(text, size)
    if ftype not in cache:
        cache[ftype] = _sample_bytes(ftype)
    return _fit(cache[ftype][0], size)


def generate(types: list[str], sizes: list[str]) -> list[list]:
    rows, cache = [], {}
    for ftype in types:
        for label in sizes:
            path = dataset_path(ftype, label)
            path.parent.mkdir(parents=True, exist_ok=True)
            data = make_bytes(ftype, SIZES[label], cache)
            path.write_bytes(data)
            source = {"BIN": "SHAKE-256, fixed seed", "TXT": "repeated text"}.get(ftype) or cache[ftype][1]
            rows.append([ftype, label, len(data), path.relative_to(ROOT.parent).as_posix(),
                         hashlib.sha256(data).hexdigest(), source])
            print(f"  {ftype:<3} {label:>5}  {len(data):>10,} bytes  {path.relative_to(ROOT.parent)}")
    with open(MANIFEST, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["file_type", "input_size", "bytes", "path", "sha256", "source"])
        w.writerows(rows)
    return rows


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--types", nargs="+", default=list(FILE_TYPES), choices=list(FILE_TYPES))
    ap.add_argument("--sizes", nargs="+", default=list(SIZES), choices=list(SIZES))
    args = ap.parse_args()
    print("Generating datasets:")
    generate(args.types, args.sizes)
    print(f"Manifest written to {MANIFEST}")


if __name__ == "__main__":
    main()
