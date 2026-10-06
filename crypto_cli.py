"""
Crypto Lab CLI - one interactive front end for the IE3082 AES-GCM + SHA-256 project.

    python crypto_cli.py                 # interactive menu (recommended)
    python crypto_cli.py --help          # one-shot commands for scripting

One-shot examples
    python crypto_cli.py sha256 text "hello world"
    python crypto_cli.py sha256 file datasets/data/TXT/1MB.txt
    python crypto_cli.py sha256 verify report.pdf 9f86d0...
    python crypto_cli.py sha256 hmac --key secret "message"
    python crypto_cli.py sha256 avalanche "hello"
    python crypto_cli.py aes encrypt "secret text" --bits 256 --aad demo
    python crypto_cli.py aes decrypt <token> --key <hex> --aad demo
    python crypto_cli.py aes encrypt-file photo.jpg --save-key photo.key
    python crypto_cli.py aes decrypt-file photo.jpg.enc photo_out.jpg --key photo.key
    python crypto_cli.py aes tamper
    python crypto_cli.py bench aes --file datasets/data/BIN/10MB.bin --trials 10
    python crypto_cli.py bench sha256 --text "abc" --trials 20
    python crypto_cli.py lab sha-demo
    python crypto_cli.py results sha256_summary.csv --filter file_type=BIN

The cryptography itself lives in src/aes_crypto.py and src/sha256_hash.py; this
file only collects input, calls those functions and prints the output. The
existing benchmark/report scripts are launched unchanged with `python -m ...`.

Text token format used by "aes encrypt"/"aes decrypt":
    token = base64( nonce (12 B) || ciphertext || tag (16 B) )
The AAD is not inside the token; the same AAD must be given again to decrypt.
"""
from __future__ import annotations

import argparse
import base64
import binascii
import csv
import os
import random
import statistics
import subprocess
import sys
import time
from dataclasses import replace
from pathlib import Path

ROOT = Path(__file__).resolve().parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

try:
    from rich import box
    from rich.console import Console
    from rich.panel import Panel
    from rich.prompt import Confirm, IntPrompt, Prompt
    from rich.table import Table
    from rich.text import Text
except ImportError:
    sys.exit("This CLI needs the 'rich' package:  pip install rich   (or: pip install -r requirements.txt)")

from src.aes_crypto import (NONCE_SIZE, TAG_SIZE, VALID_KEY_SIZES, AESGCMCipher, AuthenticationError,
                            EncryptedPayload, decrypt_file, encrypt_file, generate_key, generate_nonce,
                            verify_decryption)
from src.sha256_hash import (DEFAULT_CHUNK_SIZE, compare_hashes, hamming_distance, hash_bytes,
                             hash_file_chunked, hash_text, hmac_sha256, integrity_check,
                             normalise_digest)

console = Console()
RESULTS = ROOT / "results"
DATA_DIR = ROOT / "datasets" / "data"
MIB = 1024**2


# =============================================================== small helpers
def clean_path(s: str) -> Path:
    """Accept paths pasted or dragged into the terminal (quotes, spaces)."""
    return Path(s.strip().strip('"').strip("'")).expanduser()


def existing_file(s: str) -> Path:
    p = clean_path(s)
    if not p.is_file():
        raise FileNotFoundError(f"No such file: {p}")
    return p


def human_bytes(n: int) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return f"{n:,} B" if unit == "B" else f"{n:,.2f} {unit}"
        n /= 1024
    return f"{n}"


def parse_key(s: str) -> bytes:
    """A key given as hex (32/48/64 chars), base64, or a path to a key file."""
    s = s.strip()
    p = clean_path(s)
    if len(s) < 260 and p.is_file():
        raw = p.read_bytes()
        if len(raw) in (16, 24, 32):
            return raw
        s = raw.decode("ascii", errors="ignore").strip()
    try:
        key = bytes.fromhex(s)
    except ValueError:
        try:
            key = base64.b64decode(s, validate=True)
        except binascii.Error:
            raise ValueError("Key must be hex, base64 or a key file path") from None
    if len(key) * 8 not in VALID_KEY_SIZES:
        raise ValueError(f"Key must be 16, 24 or 32 bytes (AES-128/192/256), got {len(key)} bytes")
    return key


def save_key(key: bytes, path: Path) -> None:
    path.write_text(key.hex() + "\n", encoding="ascii")
    console.print(f"[yellow]Key written to {path}[/] (*.key is git-ignored, so it will not be committed).")


def digest_diff(a: str, b: str) -> Text:
    """b with every hex character that differs from a highlighted."""
    t = Text()
    for x, y in zip(a, b):
        t.append(y, style="bold red" if x != y else "green")
    return t


def kv_table(rows: list[tuple[str, object]], title: str | None = None) -> Table:
    t = Table(box=box.ROUNDED, show_header=False, title=title, title_style="bold cyan", expand=False)
    t.add_column(style="bold cyan", no_wrap=True)
    t.add_column(overflow="fold")
    for k, v in rows:
        t.add_row(k, v if isinstance(v, Text) else str(v))
    return t


def ok_text(ok: bool, yes: str = "PASS", no: str = "FAIL") -> Text:
    return Text(yes, style="bold green") if ok else Text(no, style="bold red")


def error(msg: str) -> None:
    console.print(Panel(str(msg), title="Error", border_style="red", expand=False))


# =============================================================== AES-GCM actions
def aes_encrypt_text(text: str, bits: int = 256, key: bytes | None = None, aad: str = "") -> dict:
    new_key = key is None
    key = key or generate_key(bits)
    payload = AESGCMCipher(key).encrypt(text.encode("utf-8"), aad.encode("utf-8"))
    token = base64.b64encode(payload.nonce + payload.ciphertext).decode()
    return {"key": key, "new_key": new_key, "payload": payload, "token": token,
            "plain_len": len(text.encode("utf-8"))}


def show_aes_encrypt(r: dict, aad: str) -> None:
    p: EncryptedPayload = r["payload"]
    console.print(kv_table([
        ("Algorithm", f"AES-{len(r['key']) * 8}-GCM"),
        ("Key (hex)", Text(r["key"].hex(), style="bold yellow")),
        ("Nonce (96-bit)", p.nonce.hex()),
        ("AAD", aad or "(none)"),
        ("Ciphertext (hex)", p.ciphertext_only.hex() or "(empty)"),
        ("Tag (128-bit)", p.tag.hex()),
        ("Sizes", f"plaintext {r['plain_len']} B -> ciphertext+tag {len(p.ciphertext)} B (+16 B tag)"),
        ("TOKEN (base64)", Text(r["token"], style="bold green")),
    ], title="AES-GCM encryption"))
    if r["new_key"]:
        console.print("[yellow]A new random key was generated. Keep it secret: you need it AND the token "
                      "(and the same AAD) to decrypt. This tool does not store it.[/]")


def aes_decrypt_text(key: bytes, token: str, aad: str = "") -> str:
    try:
        blob = base64.b64decode(token.strip(), validate=True)
    except binascii.Error:
        raise ValueError("Token is not valid base64") from None
    if len(blob) < NONCE_SIZE + TAG_SIZE:
        raise AuthenticationError("Token too short to contain a nonce and a tag")
    payload = EncryptedPayload(blob[:NONCE_SIZE], blob[NONCE_SIZE:], aad.encode("utf-8"))
    return AESGCMCipher(key).decrypt(payload).decode("utf-8", errors="replace")


def aes_encrypt_file(src: Path, dst: Path, bits: int = 256, key: bytes | None = None) -> tuple[bytes, int, float]:
    key = key or generate_key(bits)
    t0 = time.perf_counter()
    n = encrypt_file(key, src, dst)
    return key, n, time.perf_counter() - t0


def aes_decrypt_file(src: Path, dst: Path, key: bytes) -> tuple[int, float]:
    t0 = time.perf_counter()
    n = decrypt_file(key, src, dst)
    return n, time.perf_counter() - t0


def aes_tamper_demo(text: str = "Transfer Rs. 10,000 to account 1234", bits: int = 256) -> list[tuple]:
    """Encrypt once, then try to decrypt several manipulated versions. All must be rejected."""
    key = generate_key(bits)
    cipher = AESGCMCipher(key)
    p = cipher.encrypt(text.encode(), b"header")

    def flip(b: bytes, i: int) -> bytes:
        x = bytearray(b)
        x[i] ^= 0x01
        return bytes(x)

    cases = [
        ("Original (untouched)", cipher, p, True),
        ("1 bit flipped in ciphertext", cipher, replace(p, ciphertext=flip(p.ciphertext, 0)), False),
        ("1 bit flipped in tag", cipher, replace(p, ciphertext=flip(p.ciphertext, -1)), False),
        ("Wrong key", AESGCMCipher(generate_key(bits)), p, False),
        ("Wrong nonce", cipher, replace(p, nonce=generate_nonce()), False),
        ("Wrong AAD", cipher, replace(p, aad=b"other-header"), False),
        ("Truncated (last byte removed)", cipher, replace(p, ciphertext=p.ciphertext[:-1]), False),
    ]
    rows = []
    for name, c, payload, should_decrypt in cases:
        try:
            out = c.decrypt(payload).decode(errors="replace")
            result, ok = f"decrypted: {out!r}", should_decrypt
        except AuthenticationError as e:
            result, ok = f"REJECTED ({e})", not should_decrypt
        rows.append((name, "decrypt" if should_decrypt else "reject", result, ok))
    return rows


def show_tamper(rows: list[tuple]) -> None:
    t = Table(title="AES-GCM tamper detection", box=box.ROUNDED, title_style="bold cyan")
    for col in ("Case", "Expected", "Result", "As expected"):
        t.add_column(col)
    for name, exp, res, ok in rows:
        t.add_row(name, exp, res, ok_text(ok, "yes", "NO"))
    console.print(t)
    console.print("GCM checks the 128-bit tag before releasing any plaintext, so any change is detected.")


# =============================================================== SHA-256 actions
def show_digest(label: str, source: str, digest: str, extra: list[tuple] = ()) -> None:
    console.print(kv_table([("Input", source), *extra, (label, Text(digest, style="bold green"))],
                           title="SHA-256"))


def sha_file(path: Path, chunk: int = DEFAULT_CHUNK_SIZE) -> tuple[str, float]:
    t0 = time.perf_counter()
    d = hash_file_chunked(path, chunk)
    return d, time.perf_counter() - t0


def show_integrity(path: Path, expected: str) -> bool:
    res = integrity_check(path, expected)
    console.print(kv_table([
        ("File", f"{path}  ({human_bytes(path.stat().st_size)})"),
        ("Expected (trusted)", res.expected),
        ("Actual", digest_diff(res.expected, res.actual)),
        ("Differing bits", f"{res.differing_bits} / 256"),
        ("Verification", ok_text(res.match, "PASS - file unchanged", "FAIL - file was modified")),
    ], title="Integrity check"))
    return res.match


def avalanche(text: str, bit: int | None = None, trials: int = 1000) -> dict:
    msg = text.encode("utf-8")
    if not msg:
        raise ValueError("Enter at least one character")
    h0 = hash_bytes(msg)
    bit = 0 if bit is None else bit
    if not 0 <= bit < len(msg) * 8:
        raise ValueError(f"Bit index must be 0..{len(msg) * 8 - 1}")
    m = bytearray(msg)
    m[bit // 8] ^= 1 << (bit % 8)
    h1 = hash_bytes(bytes(m))
    rng = random.Random(3082)
    dists = []
    for _ in range(trials):
        b = rng.randrange(len(msg) * 8)
        x = bytearray(msg)
        x[b // 8] ^= 1 << (b % 8)
        dists.append(hamming_distance(h0, hash_bytes(bytes(x))))
    return {"msg": msg, "mod": bytes(m), "bit": bit, "h0": h0, "h1": h1,
            "changed": hamming_distance(h0, h1), "dists": dists}


def show_avalanche(r: dict) -> None:
    d = r["dists"]
    console.print(kv_table([
        ("Original input", repr(r["msg"].decode("utf-8", errors="replace"))),
        ("Modified input", f"{r['mod']!r}  (bit {r['bit']} of byte {r['bit'] // 8} flipped)"),
        ("Digest original", Text(r["h0"], style="green")),
        ("Digest modified", digest_diff(r["h0"], r["h1"])),
        ("Bits changed", f"{r['changed']} / 256  ({r['changed'] / 2.56:.1f} %)"),
        (f"{len(d)} random 1-bit flips",
         f"mean {statistics.mean(d):.2f} bits, SD {statistics.stdev(d):.2f}, min {min(d)}, max {max(d)}  "
         f"(ideal: mean 128, SD 8)"),
    ], title="Avalanche effect"))


# =============================================================== benchmarks on user input
def bench_aes(data: bytes, keys: list[int], trials: int, cpu_window: float = 0.25) -> list[dict]:
    from benchmarks.measure import cpu_percent, peak_traced_mb, summarise, timed
    mb = len(data) / MIB
    out = []
    for bits in keys:
        c = AESGCMCipher(generate_key(bits))
        c.decrypt(c.encrypt(data))                                      # warm-up, discarded
        enc, dec, ok = [], [], 0
        for _ in range(trials):
            c = AESGCMCipher(generate_key(bits))                        # new key per trial
            p, te = timed(lambda: c.encrypt(data))
            r, td = timed(lambda: c.decrypt(p))
            enc.append(te * 1000)
            dec.append(td * 1000)
            ok += verify_decryption(data, r)
        peak = peak_traced_mb(lambda: c.encrypt(data))
        cpu, _ = cpu_percent(lambda: c.encrypt(data), cpu_window)
        e, d = summarise(enc), summarise(dec)
        out.append({"name": f"AES-{bits}", "enc": e, "dec": d,
                    "thr": mb / (e["mean"] / 1000) if e["mean"] else 0.0,
                    "peak": peak, "cpu": cpu, "ok": ok, "n": trials})
    return out


def show_bench_aes(rows: list[dict], size: int) -> None:
    t = Table(title=f"AES-GCM benchmark - {human_bytes(size)} input, {rows[0]['n']} trials",
              box=box.ROUNDED, title_style="bold cyan")
    for col in ("Key", "Enc mean ms", "Enc SD", "Dec mean ms", "Dec SD", "Enc MB/s", "CPU %", "Peak MB",
                "Correct"):
        t.add_column(col, justify="right")
    for r in rows:
        t.add_row(r["name"], f"{r['enc']['mean']:.4f}", f"{r['enc']['std']:.4f}",
                  f"{r['dec']['mean']:.4f}", f"{r['dec']['std']:.4f}", f"{r['thr']:,.1f}",
                  f"{r['cpu']:.1f}", f"{r['peak']:.3f}",
                  ok_text(r["ok"] == r["n"], f"PASS {r['ok']}/{r['n']}", f"FAIL {r['n'] - r['ok']}/{r['n']}"))
    console.print(t)


def bench_sha(data: bytes, path: Path | None, trials: int, cpu_window: float = 0.25) -> dict:
    from benchmarks.measure import cpu_percent, peak_traced_mb, summarise, timed
    mb = len(data) / MIB
    ref = hash_bytes(data)
    fn = (lambda: hash_file_chunked(path)) if path else (lambda: hash_bytes(data))
    fn()                                                                # warm-up
    times, ok = [], 0
    mem_times = []
    for _ in range(trials):
        d, t = timed(fn)
        times.append(t * 1000)
        ok += compare_hashes(d, ref)
        if path:
            _, tm = timed(lambda: hash_bytes(data))
            mem_times.append(tm * 1000)
    s = summarise(times)
    return {"digest": ref, "mode": "file (64 KiB reads)" if path else "in-memory", "t": s,
            "mem": summarise(mem_times) if mem_times else None,
            "thr": mb / (s["mean"] / 1000) if s["mean"] else 0.0,
            "cpu": cpu_percent(fn, cpu_window)[0], "peak": peak_traced_mb(fn), "ok": ok, "n": trials}


def show_bench_sha(r: dict, size: int) -> None:
    s = r["t"]
    rows = [("Input size", human_bytes(size)), ("Mode", r["mode"]), ("Trials", r["n"]),
            ("Mean time", f"{s['mean']:.4f} ms"), ("Min / Max", f"{s['min']:.4f} / {s['max']:.4f} ms"),
            ("SD (CV)", f"{s['std']:.4f} ms ({s['std'] / s['mean'] * 100 if s['mean'] else 0:.1f} %)"),
            ("Throughput", f"{r['thr']:,.1f} MB/s")]
    if r["mem"]:
        rows.append(("In-memory mean", f"{r['mem']['mean']:.4f} ms "
                                       f"({size / MIB / (r['mem']['mean'] / 1000):,.1f} MB/s)"))
    rows += [("CPU (one core)", f"{r['cpu']:.1f} %"), ("Peak traced memory", f"{r['peak']:.3f} MB"),
             ("Digest", r["digest"]),
             ("Digest consistency", ok_text(r["ok"] == r["n"], f"PASS {r['ok']}/{r['n']}", "FAIL"))]
    console.print(kv_table(rows, title="SHA-256 benchmark"))


# =============================================================== project lab scripts
LAB_TASKS = {
    "datasets":     ("Generate all test datasets (BIN/TXT/PDF/JPG, 1KB-50MB, ~265 MB)",
                     ["datasets.generate_test_data"], False),
    "tests":        ("Run the whole pytest suite (AES + SHA-256)", ["pytest", "-v"], False),
    "tests-aes":    ("Run AES pytest tests only", ["pytest", "-v", "tests/test_aes.py"], False),
    "tests-sha":    ("Run SHA-256 pytest tests only", ["pytest", "-v", "tests/test_sha256.py"], False),
    "aes-selftest": ("AES correctness + tamper self-test -> correctness_tests.csv", ["benchmarks.self_test"], True),
    "sha-demo":     ("SHA-256 known-answer, integrity and avalanche demo", ["benchmarks.sha256_integrity_demo"], True),
    "aes-quick":    ("AES benchmark smoke test (~10 s) -> results/quick/", ["benchmarks.benchmark_aes", "--quick"], True),
    "sha-quick":    ("SHA-256 benchmark smoke test (~2 s) -> results/quick/",
                     ["benchmarks.benchmark_sha256", "--quick"], True),
    "aes-full":     ("FULL AES benchmark (10-20 min, overwrites results/aes_*.csv)", ["benchmarks.benchmark_aes"], True),
    "sha-full":     ("FULL SHA-256 benchmark (~70 s, overwrites results/sha256_*.csv)",
                     ["benchmarks.benchmark_sha256"], True),
    "plot-aes":     ("Draw AES graphs from results/aes_summary.csv", ["benchmarks.plot_results"], False),
    "plot-sha":     ("Draw SHA-256 graphs from results/sha256_*.csv", ["benchmarks.plot_sha256"], False),
}
NEEDS_CONFIRM = {"aes-full", "sha-full", "datasets"}


def datasets_present() -> bool:
    return (DATA_DIR / "BIN" / "1MB.bin").exists() and (DATA_DIR / "TXT" / "1MB.txt").exists()


def run_lab(task: str, extra: list[str] | None = None, interactive: bool = True) -> int:
    desc, cmd, needs_data = LAB_TASKS[task]
    if needs_data and not datasets_present():
        console.print("[yellow]The datasets in datasets/data/ have not been generated yet.[/]")
        try:
            generate = interactive and Confirm.ask("Generate them now (all types, ~265 MB)?", default=True)
        except EOFError:
            generate = False
        if generate:
            if run_lab("datasets", interactive=False) != 0:
                return 1
        else:
            console.print("Run:  python crypto_cli.py lab datasets")
            return 1
    full = [sys.executable, "-m", *cmd, *(extra or [])]
    console.rule(f"[bold cyan]{desc}")
    console.print(f"[dim]$ {' '.join(['python', '-m', *cmd, *(extra or [])])}[/]")
    t0 = time.perf_counter()
    rc = subprocess.call(full, cwd=ROOT)
    colour = "green" if rc == 0 else "red"
    console.rule(f"[{colour}]exit code {rc} - {time.perf_counter() - t0:.1f} s")
    return rc


# =============================================================== results viewer
KEY_COLUMNS = {
    "aes_summary.csv": ["key_size", "file_type", "input_size", "enc_mean_ms", "enc_std_ms", "dec_mean_ms",
                        "enc_throughput_MBps", "enc_cpu_mean_pct", "enc_peak_mean_MB", "correctness"],
    "aes_raw_trials.csv": ["key_size", "file_type", "input_size", "trial", "enc_time_ms", "dec_time_ms",
                           "enc_throughput_MBps", "enc_cpu_pct", "enc_peak_MB", "verified"],
    "sha256_summary.csv": ["file_type", "input_size", "mean_ms", "std_ms", "cv_pct", "inmemory_mean_ms",
                           "throughput_MBps", "cpu_mean_pct", "peak_mean_MB", "digest_consistency"],
    "sha256_results.csv": ["file_type", "input_size", "trial", "hash_time_ms", "inmemory_time_ms",
                           "throughput_MBps", "cpu_pct", "peak_traced_MB", "verified"],
    "sha256_chunk_size_experiment.csv": ["read_size", "mean_ms", "std_ms", "cv_pct", "throughput_MBps",
                                         "peak_traced_MB", "digest_consistency"],
    "sha256_known_answer_tests.csv": ["test", "detail", "result"],
    "sha256_integrity_avalanche.csv": ["test", "change", "differing_bits_of_256", "verification", "expected"],
    "correctness_tests.csv": ["test", "key_size", "expected", "result"],
}


def result_files() -> list[Path]:
    files = sorted(RESULTS.glob("*.csv")) + sorted(RESULTS.glob("*.txt"))
    quick = RESULTS / "quick"
    if quick.is_dir():
        files += sorted(quick.glob("*.csv")) + sorted(quick.glob("*.txt"))
    return files


def fmt_cell(v: str) -> str:
    try:
        f = float(v)
    except ValueError:
        return v
    if v.isdigit():
        return v
    return f"{f:,.4f}" if abs(f) < 1000 else f"{f:,.1f}"


def show_result(path: Path, filters: dict[str, str] | None = None, limit: int = 60, all_cols: bool = False) -> None:
    if path.suffix == ".txt":
        console.print(Panel(path.read_text(encoding="utf-8", errors="replace"), title=path.name, expand=False))
        return
    with open(path, newline="", encoding="utf-8") as f:
        rows = list(csv.DictReader(f))
    if not rows:
        console.print(f"{path.name} is empty.")
        return
    cols = list(rows[0].keys())
    if not all_cols and path.name in KEY_COLUMNS:
        cols = [c for c in KEY_COLUMNS[path.name] if c in rows[0]]
    for k, v in (filters or {}).items():
        rows = [r for r in rows if r.get(k, "").lower() == v.lower()]
    t = Table(title=f"{path.relative_to(ROOT)}  ({len(rows)} rows"
                    f"{', first ' + str(limit) if len(rows) > limit else ''})",
              box=box.SIMPLE_HEAVY, title_style="bold cyan")
    for c in cols:
        t.add_column(c, overflow="fold", min_width=min(len(c), 14))
    for r in rows[:limit]:
        cells = []
        for c in cols:
            v = fmt_cell(r.get(c, ""))
            style = "green" if v.startswith("PASS") or v == "yes" else "red" if v.startswith("FAIL") or v == "NO" else ""
            cells.append(Text(v, style=style))
        t.add_row(*cells)
    console.print(t)
    if len(cols) < len(rows[0]) if rows else False:
        console.print(f"[dim]Showing key columns only ({len(cols)} of {len(rows[0]) if rows else '?'}). "
                      "Choose 'all columns' to see everything.[/]")


def open_file(path: Path) -> None:
    if sys.platform == "win32":
        os.startfile(path)                                    # noqa: S606 - local file the user picked
    else:
        subprocess.Popen(["open" if sys.platform == "darwin" else "xdg-open", str(path)])


def environment() -> None:
    from benchmarks.measure import cpu_method, environment_info
    env = environment_info()
    env["CPU measurement"] = cpu_method()
    env["Datasets generated"] = "yes" if datasets_present() else "no (lab -> generate datasets)"
    console.print(kv_table([(k, v) for k, v in env.items()], title="Test environment"))


# =============================================================== interactive menus
def menu(title: str, options: list[tuple[str, str]], back: str = "Back") -> str:
    t = Table(box=box.ROUNDED, show_header=False, title=title, title_style="bold magenta", min_width=60)
    t.add_column(style="bold yellow", justify="right")
    t.add_column()
    for i, (_, label) in enumerate(options, 1):
        t.add_row(str(i), label)
    t.add_row("0", f"[dim]{back}[/]")
    console.print()
    console.print(t)
    choice = Prompt.ask("Choose", choices=[str(i) for i in range(len(options) + 1)], show_choices=False)
    return "0" if choice == "0" else options[int(choice) - 1][0]


def ask_bits(default: int = 256) -> int:
    return int(Prompt.ask("Key size (bits)", choices=[str(b) for b in VALID_KEY_SIZES], default=str(default)))


def ask_key_or_new(bits_prompt: bool = True) -> tuple[bytes | None, int]:
    s = Prompt.ask("Key (hex / key-file path), or press Enter to generate a new one", default="",
                   show_default=False)
    if s.strip():
        key = parse_key(s)
        return key, len(key) * 8
    return None, ask_bits() if bits_prompt else 256


def ask_file(prompt: str) -> Path:
    return existing_file(Prompt.ask(prompt))


def ask_text(prompt: str = "Text") -> str:
    console.print("[dim]Tip: type \\n for a newline.[/]")
    return Prompt.ask(prompt).replace("\\n", "\n")


def pause() -> None:
    Prompt.ask("[dim]Press Enter to continue[/]", default="", show_default=False)


def guarded(fn) -> None:
    """Run one menu action; show errors instead of crashing, Ctrl+C returns to the menu."""
    try:
        fn()
    except KeyboardInterrupt:
        console.print("\n[dim]Cancelled.[/]")
    except (AuthenticationError,) as e:
        error(f"Authentication failed - wrong key, wrong AAD or the data was modified.\n({e})")
    except Exception as e:                                    # noqa: BLE001 - show any input error nicely
        error(f"{type(e).__name__}: {e}")
    pause()


def aes_menu() -> None:
    while True:
        c = menu("AES-GCM (authenticated encryption)", [
            ("enc_text", "Encrypt text"),
            ("dec_text", "Decrypt text (key + token)"),
            ("enc_file", "Encrypt a file  -> .enc"),
            ("dec_file", "Decrypt a .enc file"),
            ("tamper", "Tamper-detection demo (modified data / wrong key / wrong AAD)"),
            ("keygen", "Generate a new random key"),
        ])
        if c == "0":
            return
        guarded(AES_ACTIONS[c])


def _i_enc_text():
    text = ask_text("Plaintext")
    key, bits = ask_key_or_new()
    aad = Prompt.ask("AAD - optional authenticated label, e.g. 'invoice-42'", default="", show_default=False)
    r = aes_encrypt_text(text, bits, key, aad)
    show_aes_encrypt(r, aad)
    if r["new_key"] and Confirm.ask("Save the key to a .key file?", default=False):
        save_key(r["key"], clean_path(Prompt.ask("Key file", default="my_aes.key")))


def _i_dec_text():
    key = parse_key(Prompt.ask("Key (hex or key-file path)"))
    token = Prompt.ask("Token (base64)")
    aad = Prompt.ask("AAD used when encrypting", default="", show_default=False)
    plain = aes_decrypt_text(key, token, aad)
    console.print(kv_table([("Algorithm", f"AES-{len(key) * 8}-GCM"), ("Tag check", ok_text(True, "VALID")),
                            ("Plaintext", Text(plain, style="bold green"))], title="AES-GCM decryption"))


def _i_enc_file():
    src = ask_file("File to encrypt")
    dst = clean_path(Prompt.ask("Output file", default=str(src) + ".enc"))
    key, bits = ask_key_or_new()
    key, n, secs = aes_encrypt_file(src, dst, bits, key)
    size = src.stat().st_size
    console.print(kv_table([
        ("Input", f"{src}  ({human_bytes(size)})"), ("Output", f"{dst}  ({human_bytes(n)})"),
        ("Algorithm", f"AES-{len(key) * 8}-GCM"), ("Key (hex)", Text(key.hex(), style="bold yellow")),
        ("File layout", "AGCM | version | 12-B nonce | ciphertext | 16-B tag (header authenticated as AAD)"),
        ("Time", f"{secs * 1000:.2f} ms incl. disk I/O  ({size / MIB / secs if secs else 0:,.1f} MB/s)"),
    ], title="File encrypted"))
    default_key = str(dst.with_suffix(".key")) if dst.suffix == ".enc" else str(dst) + ".key"
    if Confirm.ask("Save the key to a .key file?", default=True):
        save_key(key, clean_path(Prompt.ask("Key file", default=default_key)))


def _i_dec_file():
    src = ask_file("Encrypted .enc file")
    guess = str(src)[:-4] + ".decrypted" + Path(str(src)[:-4]).suffix if str(src).endswith(".enc") else str(src) + ".out"
    dst = clean_path(Prompt.ask("Output file", default=guess))
    key = parse_key(Prompt.ask("Key (hex or key-file path)"))
    n, secs = aes_decrypt_file(src, dst, key)
    console.print(kv_table([("Output", f"{dst}  ({human_bytes(n)})"), ("Tag check", ok_text(True, "VALID")),
                            ("SHA-256 of output", hash_file_chunked(dst)),
                            ("Time", f"{secs * 1000:.2f} ms incl. disk I/O")], title="File decrypted"))


def _i_tamper():
    text = Prompt.ask("Message to protect", default="Transfer Rs. 10,000 to account 1234")
    show_tamper(aes_tamper_demo(text, ask_bits()))


def _i_keygen():
    bits = ask_bits()
    key = generate_key(bits)
    console.print(kv_table([("Key size", f"{bits} bits"), ("Key (hex)", Text(key.hex(), style="bold yellow")),
                            ("Key (base64)", base64.b64encode(key).decode())], title="New AES key (OS CSPRNG)"))
    if Confirm.ask("Save it to a .key file?", default=False):
        save_key(key, clean_path(Prompt.ask("Key file", default=f"aes{bits}.key")))


AES_ACTIONS = {"enc_text": _i_enc_text, "dec_text": _i_dec_text, "enc_file": _i_enc_file,
               "dec_file": _i_dec_file, "tamper": _i_tamper, "keygen": _i_keygen}


def sha_menu() -> None:
    while True:
        c = menu("SHA-256 (hashing & integrity)", [
            ("text", "Hash text"),
            ("file", "Hash a file"),
            ("verify", "Verify a file against a trusted digest (integrity check)"),
            ("cmp_files", "Compare two files (same content?)"),
            ("cmp_digests", "Compare two digests (and count differing bits)"),
            ("avalanche", "Avalanche effect on your text (flip 1 bit)"),
            ("hmac", "HMAC-SHA-256 (keyed hash) of text"),
            ("manifest", "Verify every generated dataset against manifest.csv"),
        ])
        if c == "0":
            return
        guarded(SHA_ACTIONS[c])


def _i_sha_text():
    text = ask_text()
    show_digest("SHA-256", repr(text), hash_text(text),
                [("Bytes (UTF-8)", len(text.encode("utf-8")))])


def _i_sha_file():
    p = ask_file("File path")
    chunk = IntPrompt.ask("Read (chunk) size in bytes", default=DEFAULT_CHUNK_SIZE)
    d, secs = sha_file(p, chunk)
    size = p.stat().st_size
    show_digest("SHA-256", str(p), d, [
        ("Size", human_bytes(size)), ("Chunk size", f"{chunk:,} B"),
        ("Time", f"{secs * 1000:.3f} ms  ({size / MIB / secs if secs else 0:,.1f} MB/s)")])
    if sys.platform == "win32":
        console.print(f"[dim]Cross-check:  certutil -hashfile \"{p}\" SHA256[/]")


def _i_verify():
    p = ask_file("File path")
    show_integrity(p, Prompt.ask("Trusted reference digest (64 hex chars)"))


def _i_cmp_files():
    a, b = ask_file("First file"), ask_file("Second file")
    da, db = hash_file_chunked(a), hash_file_chunked(b)
    same = compare_hashes(da, db)
    console.print(kv_table([("File A", f"{a}  ({human_bytes(a.stat().st_size)})"), ("SHA-256 A", da),
                            ("File B", f"{b}  ({human_bytes(b.stat().st_size)})"), ("SHA-256 B", digest_diff(da, db)),
                            ("Differing bits", f"{hamming_distance(da, db)} / 256"),
                            ("Result", ok_text(same, "IDENTICAL content", "DIFFERENT content"))],
                           title="File comparison"))


def _i_cmp_digests():
    a = normalise_digest(Prompt.ask("Digest A"))
    b = normalise_digest(Prompt.ask("Digest B"))
    console.print(kv_table([("A", a), ("B", digest_diff(a, b)),
                            ("Differing bits", f"{hamming_distance(a, b)} / 256"),
                            ("Match", ok_text(compare_hashes(a, b), "MATCH", "NO MATCH"))], title="Digest comparison"))


def _i_avalanche():
    text = Prompt.ask("Text", default="IE3082 Cryptography")
    bit = IntPrompt.ask(f"Bit to flip (0..{len(text.encode()) * 8 - 1})", default=0)
    show_avalanche(avalanche(text, bit))


def _i_hmac():
    key = Prompt.ask("Secret key (text)", password=True)
    text = ask_text("Message")
    tag = hmac_sha256(key.encode("utf-8"), text.encode("utf-8"))
    console.print(kv_table([("Message", repr(text)), ("HMAC-SHA-256", Text(tag, style="bold green")),
                            ("Plain SHA-256", hash_text(text))], title="HMAC-SHA-256"))
    console.print("[dim]Only someone with the key can produce the HMAC tag; anyone can compute the plain hash.[/]")


def verify_manifest() -> int:
    from datasets.generate_test_data import MANIFEST
    if not MANIFEST.exists() or not datasets_present():
        raise FileNotFoundError("Datasets not generated yet - use 'Run project lab scripts' -> generate datasets")
    with open(MANIFEST, newline="") as f:
        rows = list(csv.DictReader(f))
    t = Table(title="Dataset integrity vs manifest.csv", box=box.SIMPLE_HEAVY, title_style="bold cyan")
    for c in ("Type", "Size", "Bytes", "SHA-256 (first 16)", "Result"):
        t.add_column(c)
    bad = 0
    for r in rows:
        p = ROOT / r["path"]
        if not p.exists():
            t.add_row(r["file_type"], r["input_size"], "-", "-", ok_text(False, no="MISSING"))
            bad += 1
            continue
        d = hash_file_chunked(p)
        ok = compare_hashes(d, r["sha256"]) and p.stat().st_size == int(r["bytes"])
        bad += not ok
        t.add_row(r["file_type"], r["input_size"], f"{p.stat().st_size:,}", d[:16] + "...", ok_text(ok))
    console.print(t)
    console.print(ok_text(bad == 0, "All datasets match the manifest.", f"{bad} file(s) do not match."))
    return bad


SHA_ACTIONS = {"text": _i_sha_text, "file": _i_sha_file, "verify": _i_verify, "cmp_files": _i_cmp_files,
               "cmp_digests": _i_cmp_digests, "avalanche": _i_avalanche, "hmac": _i_hmac,
               "manifest": verify_manifest}


def bench_menu() -> None:
    while True:
        c = menu("Benchmark your own input", [
            ("aes", "AES-GCM: time / throughput / CPU / memory for AES-128/192/256"),
            ("sha", "SHA-256: time / throughput / CPU / memory"),
            ("both", "AES-256-GCM vs SHA-256 on the same input"),
        ])
        if c == "0":
            return
        guarded(lambda: _i_bench(c))


def _ask_input_data() -> tuple[bytes, Path | None, str]:
    src = Prompt.ask("Input", choices=["file", "text", "dataset", "random"], default="file")
    if src == "file":
        p = ask_file("File path")
        return p.read_bytes(), p, str(p)
    if src == "dataset":
        if not datasets_present():
            raise FileNotFoundError("Datasets not generated yet - use 'Run project lab scripts' first")
        from datasets.generate_test_data import FILE_TYPES, SIZES, dataset_path
        ft = Prompt.ask("File type", choices=list(FILE_TYPES), default="BIN")
        sz = Prompt.ask("Size", choices=list(SIZES), default="1MB")
        p = dataset_path(ft, sz)
        return p.read_bytes(), p, f"{ft} {sz} dataset"
    if src == "random":
        kb = IntPrompt.ask("Size in KB", default=1024)
        return os.urandom(kb * 1024), None, f"{kb} KB random bytes"
    t = ask_text()
    return t.encode("utf-8"), None, repr(t)


def _i_bench(which: str) -> None:
    data, path, label = _ask_input_data()
    trials = IntPrompt.ask("Trials", default=10)
    if trials < 1:
        raise ValueError("Trials must be >= 1")
    console.print(f"[dim]Benchmarking {label} ({human_bytes(len(data))}) ...[/]")
    if which in ("aes", "both"):
        keys = list(VALID_KEY_SIZES) if which == "aes" else [256]
        with console.status("Running AES-GCM ..."):
            rows = bench_aes(data, keys, trials)
        show_bench_aes(rows, len(data))
    if which in ("sha", "both"):
        with console.status("Running SHA-256 ..."):
            r = bench_sha(data, path, trials)
        show_bench_sha(r, len(data))
    if which == "both":
        a = rows[0]["thr"]
        console.print(f"AES-256-GCM encrypt: [bold]{a:,.1f} MB/s[/]   SHA-256 ({r['mode']}): "
                      f"[bold]{r['thr']:,.1f} MB/s[/]")
    if len(data) < 100 * 1024:
        console.print("[yellow]Small input: fixed per-call overhead dominates, so MB/s is not raw algorithm "
                      "speed (see README 'Known limitations').[/]")


def lab_menu() -> None:
    while True:
        c = menu("Run project lab scripts" + ("" if datasets_present() else "  [red](datasets not generated)[/]"),
                 [(k, f"{v[0]}  [dim]{k}[/]") for k, v in LAB_TASKS.items()])
        if c == "0":
            return

        def go(task=c):
            if task in NEEDS_CONFIRM and not Confirm.ask(f"{LAB_TASKS[task][0]} - continue?", default=True):
                return
            run_lab(task)
        guarded(go)


def results_menu() -> None:
    while True:
        files = result_files()
        graphs = sorted((RESULTS / "graphs").glob("*.png")) if (RESULTS / "graphs").is_dir() else []
        opts = [(str(p), f"{p.relative_to(RESULTS).as_posix()}") for p in files]
        opts.append(("graphs", f"Open a graph image ({len(graphs)} PNG files)"))
        c = menu("Results (CSV / TXT produced by the benchmarks)", opts)
        if c == "0":
            return
        if c == "graphs":
            def pick():
                if not graphs:
                    raise FileNotFoundError("No graphs yet - run plot-aes / plot-sha in the lab menu")
                g = menu("Graphs", [(str(p), p.name) for p in graphs])
                if g != "0":
                    open_file(Path(g))
                    console.print(f"Opened {Path(g).name}")
            guarded(pick)
            continue

        def view(path=Path(c)):
            filt, all_cols = {}, False
            if path.suffix == ".csv":
                all_cols = Prompt.ask("Columns", choices=["key", "all"], default="key") == "all"
                f = Prompt.ask("Filter (e.g. file_type=BIN, input_size=10MB) or Enter for none",
                               default="", show_default=False)
                for part in f.split(","):
                    if "=" in part:
                        k, v = part.split("=", 1)
                        filt[k.strip()] = v.strip()
            show_result(path, filt, limit=200, all_cols=all_cols)
        guarded(view)


def interactive() -> None:
    console.print(Panel.fit(
        "[bold]IE3082 Crypto Lab[/]  -  AES-GCM encryption + SHA-256 hashing\n"
        "[dim]Type the number of an option. Ctrl+C cancels the current action.[/]",
        border_style="magenta"))
    if not datasets_present():
        console.print("[yellow]Note: benchmark datasets are not generated yet "
                      "(menu 4 -> 'datasets').[/]")
    while True:
        try:
            c = menu("Main menu", [
                ("aes", "AES-GCM: encrypt / decrypt text and files"),
                ("sha", "SHA-256: hash text / files, integrity, avalanche, HMAC"),
                ("bench", "Benchmark your own input (file, text, dataset, random)"),
                ("lab", "Run project lab scripts (datasets, tests, demos, benchmarks, graphs)"),
                ("results", "View results (CSV tables, environment, graphs)"),
                ("env", "Show test environment (CPU, RAM, versions)"),
            ], back="Exit")
        except (KeyboardInterrupt, EOFError):
            break
        if c == "0":
            break
        if c == "env":
            guarded(environment)
        else:
            try:
                {"aes": aes_menu, "sha": sha_menu, "bench": bench_menu, "lab": lab_menu,
                 "results": results_menu}[c]()
            except (KeyboardInterrupt, EOFError):
                console.print()
    console.print("Bye.")


# =============================================================== one-shot commands
def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(prog="crypto_cli.py", description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd")

    aes = sub.add_parser("aes", help="AES-GCM encrypt / decrypt").add_subparsers(dest="action", required=True)
    p = aes.add_parser("encrypt", help="encrypt text -> key + token")
    p.add_argument("text")
    p.add_argument("--bits", type=int, choices=VALID_KEY_SIZES, default=256)
    p.add_argument("--key", help="hex key or key file (default: new random key)")
    p.add_argument("--aad", default="")
    p.add_argument("--save-key", type=Path)
    p = aes.add_parser("decrypt", help="decrypt a token")
    p.add_argument("token")
    p.add_argument("--key", required=True)
    p.add_argument("--aad", default="")
    p = aes.add_parser("encrypt-file")
    p.add_argument("src")
    p.add_argument("dst", nargs="?")
    p.add_argument("--bits", type=int, choices=VALID_KEY_SIZES, default=256)
    p.add_argument("--key")
    p.add_argument("--save-key", type=Path)
    p = aes.add_parser("decrypt-file")
    p.add_argument("src")
    p.add_argument("dst")
    p.add_argument("--key", required=True)
    p = aes.add_parser("tamper", help="tamper-detection demo")
    p.add_argument("--text", default="Transfer Rs. 10,000 to account 1234")
    p.add_argument("--bits", type=int, choices=VALID_KEY_SIZES, default=256)
    p = aes.add_parser("keygen")
    p.add_argument("--bits", type=int, choices=VALID_KEY_SIZES, default=256)
    p.add_argument("--save-key", type=Path)

    sha = sub.add_parser("sha256", help="SHA-256 hashing / integrity").add_subparsers(dest="action", required=True)
    p = sha.add_parser("text")
    p.add_argument("text")
    p = sha.add_parser("file")
    p.add_argument("path")
    p.add_argument("--chunk", type=int, default=DEFAULT_CHUNK_SIZE)
    p = sha.add_parser("verify", help="file vs trusted digest")
    p.add_argument("path")
    p.add_argument("digest")
    p = sha.add_parser("compare", help="compare two files")
    p.add_argument("a")
    p.add_argument("b")
    p = sha.add_parser("avalanche")
    p.add_argument("text")
    p.add_argument("--bit", type=int, default=0)
    p = sha.add_parser("hmac")
    p.add_argument("text")
    p.add_argument("--key", required=True)
    sha.add_parser("manifest", help="verify all datasets against manifest.csv")

    b = sub.add_parser("bench", help="benchmark your own input")
    b.add_argument("algo", choices=["aes", "sha256", "both"])
    g = b.add_mutually_exclusive_group(required=True)
    g.add_argument("--file")
    g.add_argument("--text")
    g.add_argument("--random-kb", type=int)
    b.add_argument("--trials", type=int, default=10)
    b.add_argument("--keys", type=int, nargs="+", choices=VALID_KEY_SIZES, default=list(VALID_KEY_SIZES))

    lab = sub.add_parser("lab", help="run a project script: " + ", ".join(LAB_TASKS))
    lab.add_argument("task", choices=list(LAB_TASKS))
    lab.add_argument("extra", nargs=argparse.REMAINDER, help="extra arguments passed to the script")

    r = sub.add_parser("results", help="show a results CSV/TXT as a table")
    r.add_argument("name", nargs="?", help="file name in results/ (omit to list)")
    r.add_argument("--filter", action="append", default=[], help="column=value (repeatable)")
    r.add_argument("--all-columns", action="store_true")
    r.add_argument("--limit", type=int, default=60)

    sub.add_parser("env", help="show the test environment")
    return ap


def one_shot(a: argparse.Namespace) -> int:
    if a.cmd == "aes":
        if a.action == "encrypt":
            r = aes_encrypt_text(a.text, a.bits, parse_key(a.key) if a.key else None, a.aad)
            show_aes_encrypt(r, a.aad)
            if a.save_key:
                save_key(r["key"], a.save_key)
        elif a.action == "decrypt":
            console.print(Text(aes_decrypt_text(parse_key(a.key), a.token, a.aad), style="bold green"))
        elif a.action == "encrypt-file":
            src = existing_file(a.src)
            dst = clean_path(a.dst) if a.dst else Path(str(src) + ".enc")
            key, n, secs = aes_encrypt_file(src, dst, a.bits, parse_key(a.key) if a.key else None)
            console.print(kv_table([("Output", f"{dst} ({human_bytes(n)})"), ("Key (hex)", key.hex()),
                                    ("Time", f"{secs * 1000:.2f} ms")], title="File encrypted"))
            if a.save_key:
                save_key(key, a.save_key)
        elif a.action == "decrypt-file":
            n, secs = aes_decrypt_file(existing_file(a.src), clean_path(a.dst), parse_key(a.key))
            console.print(f"Decrypted {human_bytes(n)} -> {a.dst} in {secs * 1000:.2f} ms (tag VALID)")
        elif a.action == "tamper":
            rows = aes_tamper_demo(a.text, a.bits)
            show_tamper(rows)
            return 0 if all(r[3] for r in rows) else 1
        elif a.action == "keygen":
            key = generate_key(a.bits)
            console.print(key.hex())
            if a.save_key:
                save_key(key, a.save_key)
    elif a.cmd == "sha256":
        if a.action == "text":
            show_digest("SHA-256", repr(a.text), hash_text(a.text))
        elif a.action == "file":
            p = existing_file(a.path)
            d, secs = sha_file(p, a.chunk)
            show_digest("SHA-256", str(p), d, [("Size", human_bytes(p.stat().st_size)),
                                               ("Time", f"{secs * 1000:.3f} ms")])
        elif a.action == "verify":
            return 0 if show_integrity(existing_file(a.path), a.digest) else 1
        elif a.action == "compare":
            da, db = hash_file_chunked(existing_file(a.a)), hash_file_chunked(existing_file(a.b))
            console.print(kv_table([("A", da), ("B", digest_diff(da, db)),
                                    ("Result", ok_text(da == db, "IDENTICAL", "DIFFERENT"))]))
            return 0 if da == db else 1
        elif a.action == "avalanche":
            show_avalanche(avalanche(a.text, a.bit))
        elif a.action == "hmac":
            console.print(hmac_sha256(a.key.encode(), a.text.encode()))
        elif a.action == "manifest":
            return 1 if verify_manifest() else 0
    elif a.cmd == "bench":
        if a.file:
            path = existing_file(a.file)
            data = path.read_bytes()
        else:
            path = None
            data = a.text.encode() if a.text is not None else os.urandom(a.random_kb * 1024)
        if a.algo in ("aes", "both"):
            show_bench_aes(bench_aes(data, sorted(a.keys), a.trials), len(data))
        if a.algo in ("sha256", "both"):
            show_bench_sha(bench_sha(data, path, a.trials), len(data))
    elif a.cmd == "lab":
        return run_lab(a.task, a.extra, interactive=sys.stdin.isatty())
    elif a.cmd == "results":
        if not a.name:
            for p in result_files():
                console.print(p.relative_to(RESULTS).as_posix())
            return 0
        path = RESULTS / a.name
        if not path.exists():
            raise FileNotFoundError(f"{path} not found")
        filt = dict(f.split("=", 1) for f in a.filter if "=" in f)
        show_result(path, filt, a.limit, a.all_columns)
    elif a.cmd == "env":
        environment()
    return 0


def main() -> None:
    args = build_parser().parse_args()
    if args.cmd is None:
        interactive()
        return
    try:
        sys.exit(one_shot(args))
    except AuthenticationError as e:
        error(f"Authentication failed - wrong key, wrong AAD or modified data. ({e})")
    except Exception as e:                                    # noqa: BLE001
        error(f"{type(e).__name__}: {e}")
    sys.exit(2)


if __name__ == "__main__":
    main()
