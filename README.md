# IE3082 Cryptography – AES / Symmetric Cryptography Component

**Student:** P.D.S. Dhananjana (IT23777590) · **Module:** IE3082 Cryptography, SLIIT, Y3S2 2026

This component implements **AES-128/192/256 in Galois/Counter Mode (AES-GCM)** and benchmarks it
for the group assignment. It measures time, CPU, memory and throughput across key sizes, input sizes
and file types. Every number in the report must come from the CSV files that this code produces.

## Contribution

- Secure AES-GCM implementation (`src/aes_crypto.py`): CSPRNG keys, 96-bit random nonces, nonce-reuse guard,
  128-bit tag, strict rejection of tampered data, file encryption.
- Reproducible datasets (`datasets/`): 1 KB – 50 MB in BIN, TXT, PDF and JPG, with SHA-256 manifest.
- Automated benchmark (`benchmarks/`): 3 key sizes × 6 sizes × 4 types, 10 trials + warm-up, time/CPU/RAM/throughput,
  raw and summary CSVs, environment record, correctness CSV.
- 70 automated pytest tests including NIST/McGrew–Viega known-answer vectors and tamper tests.
- Graph generation from the real CSVs.

## Folder structure

```
crypto-assignment/
├── src/
│   ├── __init__.py
│   └── aes_crypto.py            AES-GCM implementation (no measurement code)
├── benchmarks/
│   ├── __init__.py
│   ├── measure.py               timing / CPU / memory helpers, environment capture
│   ├── self_test.py             correctness + tamper checks -> correctness_tests.csv
│   ├── benchmark_aes.py         the benchmark -> aes_raw_trials.csv, aes_summary.csv
│   └── plot_results.py          graphs from aes_summary.csv -> results/graphs/*.png
├── datasets/
│   ├── __init__.py
│   ├── generate_test_data.py    reproducible test inputs
│   ├── samples/                 (optional) your own sample.pdf / sample.jpg
│   ├── data/                    generated files (git-ignored, ~265 MB)
│   └── manifest.csv             SHA-256 of every generated input
├── tests/
│   └── test_aes.py              pytest suite
├── results/
│   ├── aes_raw_trials.csv       one row per trial      (after full benchmark)
│   ├── aes_summary.csv          statistics per config  (after full benchmark)
│   ├── correctness_tests.csv
│   ├── environment.txt
│   ├── graphs/                  fig1 … fig7 PNG
│   └── quick/                   smoke-test output (git-ignored, NOT for the report)
├── pytest.ini
├── requirements.txt
├── .gitignore
└── README.md
```

## Requirements

- Windows 10/11 (also runs on Linux/macOS; the cycle-based CPU method is Windows-only, see below)
- Python **3.10 or newer** (developed with 3.13.9)
- `cryptography` (AES-GCM via OpenSSL), `psutil` (CPU/RSS), `matplotlib` (graphs), `pytest` (tests)

## Setup (Windows PowerShell)

Run all commands from the `crypto-assignment` folder.

```powershell
py -3 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
```

If activation is blocked ("running scripts is disabled"), run once:
`Set-ExecutionPolicy -Scope CurrentUser RemoteSigned`, or skip activation and call `.\.venv\Scripts\python.exe` directly.

## Usage

```powershell
python -m datasets.generate_test_data            # 1. create inputs (all types, all sizes)
python -m pytest -v                              # 2. unit tests
python -m benchmarks.self_test                   # 3. (optional) correctness CSV only
python -m benchmarks.benchmark_aes --quick       # 4a. 10-second smoke test -> results/quick/
python -m benchmarks.benchmark_aes               # 4b. FULL benchmark -> results/
python -m benchmarks.plot_results                # 5. graphs from results/aes_summary.csv
```

Always use `python -m ...` from the project root (not `python benchmarks\benchmark_aes.py`), so the
`src`, `benchmarks` and `datasets` packages import correctly.

Useful options:

| Command | Purpose |
|---|---|
| `benchmark_aes --types BIN` | only random binary data (fastest full run) |
| `benchmark_aes --trials 20` | more trials (minimum 10 is enforced) |
| `benchmark_aes --cpu-window 0.5` | longer CPU sampling window |
| `plot_results --file-type TXT` | graphs for another data type |
| `plot_results --compare-size 10MB` | size used in the key-size bar chart (default: largest) |
| `plot_results --filetype-size 10MB --filetype-key 256` | settings of the file-type chart |

A full run takes roughly 10–20 minutes (72 configurations × 10 trials). Most of that time goes on the separate
CPU and memory measurement runs.

## Methodology

**Crypto.** AES-GCM from `cryptography` (OpenSSL backend). Keys come from `AESGCM.generate_key()` (OS CSPRNG),
with a fresh 96-bit nonce from `os.urandom(12)` for every message, a 128-bit tag, and AAD that binds key size, file type
and size. `AESGCMCipher` stops if a nonce would repeat under its key, and it refuses more than 2³² messages per key
(the SP 800-38D limit for random nonces). A tag failure raises `AuthenticationError` and returns no plaintext.
ECB is never used, and no key is hard-coded, printed or written to disk.

**Datasets.** 1 KB = 1,024 B and 1 MB = 1,048,576 B. BIN is SHAKE-256 output with a fixed seed: random-looking,
incompressible and identical on every run. TXT is repeated ASCII text. PDF and JPG are a real document and image
repeated or truncated to size. They are generated deterministically by matplotlib unless you place your own files at
`datasets/samples/sample.pdf` and `sample.jpg`. `manifest.csv` records the SHA-256 of every input.
**AES processes bytes, not file formats.** Every 16-byte block costs the same regardless of content, so file type is
not expected to change speed beyond trial-to-trial noise. The TXT/PDF/JPG/BIN comparison is an experimental check of
that expectation, not a claim made in advance.

**Per configuration** (file type, input size):
1. The input is read from disk once; file I/O is never timed.
2. One warm-up encrypt/decrypt per key size is discarded (library loading, first allocations, CPU clock ramp-up).
3. 10 measured trials. Within each trial all three key sizes run in an order that **rotates** each trial, so slow
   drift such as heat, turbo or background load is shared evenly between AES-128/192/256.
4. Each trial uses a **new key**. The measurements are:
   - **Time:** `time.perf_counter()` around one `encrypt` and one `decrypt` call, with GC disabled during the call
     (as `timeit` does). Timed encryption includes nonce generation and the nonce-reuse check.
   - **Correctness:** decrypted output compared byte-for-byte with the input (`PASS`/`FAIL` in every CSV row).
   - **Memory** (separate run): `tracemalloc` peak of Python-allocated memory during one call, plus process RSS.
   - **CPU** (separate run): the operation repeated for ≥ 0.25 s; CPU used ÷ wall time, as % of **one** logical core.
5. Statistics: mean, min, max and **sample** standard deviation (`statistics.stdev`, n − 1), plus the coefficient of
   variation. Throughput = input MB ÷ mean time.

**CPU measurement on Windows (important for the viva).** Windows charges process CPU *time*
(`GetProcessTimes`, used by `psutil`) at scheduler-tick granularity. On the development laptop (Intel i9-14900HX,
hybrid P/E cores) this was tested directly: a pure busy loop read anywhere from 0 % to 81 % through psutil, while the
hardware cycle counter showed the thread running the whole time. The benchmark therefore measures CPU as
`QueryProcessCycleTime` cycles ÷ (calibrated TSC rate × wall time). That value is exact, reads ≈100 % for a busy loop
and ≈0.4 % for a sleeping one. The psutil figure is still stored (`*_cpu_os_pct` columns) for transparency.
`environment.txt` records which method was used. On Linux/macOS psutil is used.

## Outputs

| File | Content |
|---|---|
| `results/aes_raw_trials.csv` | every trial: key, type, size, enc/dec ms, throughput, CPU (both methods), peak MB, RSS, PASS/FAIL |
| `results/aes_summary.csv` | per configuration: mean/min/max/SD/CV of enc & dec time, throughput, CPU mean/SD, memory, correctness `PASS 10/10` |
| `results/correctness_tests.csv` | KATs, round trips, tamper/wrong-key/nonce/AAD rejection, invalid key sizes, nonce uniqueness |
| `results/environment.txt` | CPU, cores, RAM, OS, Python/cryptography/OpenSSL/psutil versions, power plan, settings, start/end, failures |
| `results/graphs/fig1…fig7.png` | generated only from `aes_summary.csv` |

If the three key-size lines lie exactly on top of each other in a graph (typically memory), that is the data:
memory does not depend on key size.

## Security notes

- Nonce reuse under one key breaks GCM confidentiality and allows tag forgery. The guard in `AESGCMCipher` plus
  96-bit random nonces prevent it. Reuse one `AESGCMCipher` object for all messages under the same key.
  `encrypt_data()` is a one-shot convenience wrapper.
- Fixed zero nonces appear **only** in known-answer tests, because a test vector needs fixed input.
- `encrypt_file` stores `AGCM | version | nonce | ciphertext‖tag`. The header is authenticated as AAD.
- Out of scope for a benchmarking prototype: key storage (use a KMS/HSM), key rotation policy, secure erasure of keys
  from Python memory, streaming encryption of very large files (the one-shot API holds whole files in RAM).

## Reproducibility checklist

1. Record `pip freeze > results\pip_freeze.txt` next to the results.
2. Plug in AC power, choose the *Best performance* power mode, and close other applications (browser, Discord, cloud sync).
3. Check AES hardware support: Sysinternals **Coreinfo** (`coreinfo64 -f`, look for `AES *`), or check the CPU's
   Intel ARK / AMD spec page.
4. Run `generate_test_data`, check that the hashes in `manifest.csv` are unchanged, then run `benchmark_aes`, then `plot_results`.
5. Keep all four CSV/TXT files and the PNGs together. Do not edit the CSVs by hand.
6. Optional: repeat on another day and compare. Absolute times differ between machines; the trends should hold.
