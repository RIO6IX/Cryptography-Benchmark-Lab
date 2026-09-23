# IE3082 Cryptography – SHA-256 / Hashing + Data Testing Component

**Student:** G.C.I. Sampath (IT23548046) · **Module:** IE3082 Cryptography, SLIIT, Y3S2 2026

This component implements SHA-256 hashing of text, bytes and files, verifies file integrity against trusted
reference digests, demonstrates the avalanche effect, and benchmarks SHA-256 (time, CPU, memory, throughput)
over 6 input sizes and 4 file types. It shares the dataset generator and measurement helpers with the AES
component, so both algorithms are tested on **identical inputs** with the **same measurement method**.
Every number in the report must come from the CSV files that this code produces.

## Contribution

- `src/sha256_hash.py`: `hash_text`, `hash_bytes`, `hash_file`, `hash_file_chunked`, `verify_file_hash`,
  `compare_hashes`, `integrity_check`, plus `hamming_distance` and `hmac_sha256` (to show the difference
  between a plain hash and a keyed MAC).
- `benchmarks/sha256_integrity_demo.py`: known-answer tests, original vs modified file integrity demonstration,
  1,000-trial avalanche experiment.
- `benchmarks/benchmark_sha256.py`: 4 file types × 6 sizes × 10 trials + warm-up; time, CPU, memory,
  throughput, digest verification; chunk-size experiment.
- `benchmarks/plot_sha256.py`: six graphs generated only from the CSV files.
- `tests/test_sha256.py`: 63 pytest tests (published test vectors, chunk boundaries, integrity pass/fail,
  invalid paths, a 20 MiB file, HMAC vectors).
- Shared dataset generator (`datasets/generate_test_data.py`), jointly with the AES component.

## What SHA-256 is for (and is not)

| | SHA-256 | HMAC-SHA-256 | AES-GCM (other component) |
|---|---|---|---|
| Key | none | secret key | secret key |
| Reversible | **no** (one-way; cannot be "decrypted") | no | yes, with the key |
| Provides | integrity **against a trusted reference digest** | integrity + authenticity (key holder) | confidentiality + integrity |
| Used here for | file integrity checking, avalanche test | contrast only (`hmac_sha256`) | – |

- SHA-256 is **not broken**. No attack on the full 64-round function beats generic brute force
  (about 2^256 for a preimage and 2^128 for a collision).
- A plain digest detects change **only if the reference digest is trusted**. An attacker who can replace both the
  file and its digest will pass verification. Authentication needs HMAC or a digital signature.
- **Never store passwords as raw SHA-256.** It is fast and unsalted. Use Argon2id, scrypt or PBKDF2.
- `SHA-256(key || message)` is **not** a MAC (length-extension attack). Use HMAC.

## Folder structure (SHA-256 files)

```
crypto-assignment/
├── src/sha256_hash.py                 hashing + integrity functions (no measurement code)
├── benchmarks/
│   ├── measure.py                     shared: timing / CPU / memory helpers, environment capture
│   ├── sha256_integrity_demo.py       known-answer tests, integrity demo, avalanche experiment
│   ├── benchmark_sha256.py            performance benchmark + chunk-size experiment
│   └── plot_sha256.py                 graphs from the CSVs
├── datasets/generate_test_data.py     shared: 1 KB – 50 MB, BIN/TXT/PDF/JPG + manifest.csv
├── tests/test_sha256.py               pytest suite
└── results/
    ├── sha256_results.csv                   one row per trial (raw data)
    ├── sha256_summary.csv                   mean/min/max/SD/CV per configuration
    ├── sha256_chunk_size_experiment.csv     4 KiB / 64 KiB / 1 MiB / whole-file reads
    ├── sha256_known_answer_tests.csv        test vectors, chunked == one-shot, certutil cross-check
    ├── sha256_integrity_avalanche.csv       original vs modified file digests + verification
    ├── sha256_avalanche_distribution.csv    1,000 single-bit flips
    ├── sha256_environment.txt               CPU, RAM, OS, Python, OpenSSL, settings, start/end
    ├── integrity_demo/                      original + modified copies (git-ignored, re-created)
    └── graphs/sha256_*.png                  six figures
```

## Setup (Windows PowerShell, from the `crypto-assignment` folder)

```powershell
py -3 -m venv .venv                         # 1. create virtual environment
.\.venv\Scripts\Activate.ps1                 # 2. activate it
python -m pip install --upgrade pip
pip install -r requirements.txt              # 3. install dependencies (hashlib is built in, not listed)
```

If activation is blocked, run `Set-ExecutionPolicy -Scope CurrentUser RemoteSigned` once, or skip activation
and use `.\.venv\Scripts\python.exe` instead of `python`. Python 3.10 or newer is required (developed with 3.13.9).

## Run

```powershell
python -m datasets.generate_test_data              # 4. datasets + manifest.csv (~265 MB, skip if already present)
python -m pytest -v tests/test_sha256.py           # 5. unit tests            -> expect "63 passed"
python -m benchmarks.sha256_integrity_demo         # 6. integrity demo       -> expect "ALL CHECKS PASSED"
python -m benchmarks.benchmark_sha256 --quick      #    optional 2-second smoke test -> results/quick/
python -m benchmarks.benchmark_sha256              # 7. full benchmark (~70 s) -> expect "Digest verification failures: 0"
python -m benchmarks.plot_sha256                   # 8. graphs               -> results/graphs/sha256_*.png
```

Always use `python -m ...` from the project root so that `src`, `benchmarks` and `datasets` import correctly.
Independent cross-check of any digest: `certutil -hashfile datasets\data\TXT\1MB.txt SHA256`.

Options: `benchmark_sha256 --types BIN`, `--trials 20` (minimum 10), `--cpu-window 0.5`, `--chunk-file 10MB`.

## Method

**Implementation.** `hashlib.sha256` (OpenSSL backend). Files are always opened in **binary mode** (`"rb"`).
Text mode would translate `\r\n` on Windows and change the digest. `hash_text` encodes explicitly as UTF-8.
`hash_file` reads **64 KiB chunks** and feeds them to `update()`. SHA-256 processes 512-bit blocks
sequentially and keeps only a 256-bit state, so chunked hashing gives exactly the same digest as a single call
while memory stays constant. Tests and the known-answer run confirm the equality for chunk sizes from
1 byte to larger than the file. Comparisons use `hmac.compare_digest` after validating the hex format.

**Default chunk size: 64 KiB.** In the chunk-size experiment on the 50 MB file it was the fastest read size, and it
kept peak traced memory at about 0.13 MB. 4 KiB was slower because it needs 16× more `read()`/`update()` calls.
1 MiB and whole-file reads were slower and used 2 MB and 50 MB (see `sha256_chunk_size_experiment.csv`).
Peak memory is about **2 × the chunk size**, because the previous chunk is released only after the next one is read.

**Datasets.** Shared with AES. 1 KB = 1,024 B and 1 MB = 1,048,576 B, with the exact sizes checked before every run. BIN is
deterministic SHAKE-256 output (random-looking, identical on every machine and run, unlike `os.urandom`),
TXT is repeated ASCII, and PDF/JPG are a PDF/JPEG (generated with matplotlib unless you put your own in
`datasets/samples/`) repeated or truncated to size. `manifest.csv` holds the SHA-256 of
every file and serves as the **trusted reference digest**. **SHA-256 hashes a byte stream.** It never parses
the format, so the work depends only on the length (⌈(ℓ + 65)/512⌉ compression calls for ℓ bits). File types are
compared at **equal byte sizes**, which makes the file-type comparison controlled. It is an experimental check that
content does not matter, not a claim that the extension affects speed.

**Per configuration** (file type × size): 1 warm-up (discarded), then 10 trials, each measuring:
- **File hashing time:** `time.perf_counter()` around `hash_file()`, GC disabled during the call. This includes
  `open()` and reading from the OS file cache.
- **In-memory time:** `hash_bytes()` on the same bytes already in RAM. File time minus in-memory time is the I/O share
  (`io_share_pct`).
- **CPU:** separate run, `hash_file()` repeated for ≥ 0.25 s, as % of **one** logical core. On Windows it is
  measured from `QueryProcessCycleTime` cycles, because psutil's CPU-time counter is too coarse. The psutil value is
  kept in `cpu_os_pct` for transparency (see the AES README for the full explanation).
- **Memory:** separate run, `tracemalloc` peak of Python allocations during one `hash_file()` call, plus process RSS.
- **Verification:** the file digest and the in-memory digest must both equal the manifest digest (`PASS 10/10`).

Statistics: mean, min, max, **sample** SD (n − 1), CV = SD / mean. Throughput = size in MB ÷ mean time.

**Integrity demo.** A copy of the 1 MB TXT file (PASS), then copies with 1 bit flipped, 1 character replaced and
1 byte appended (all must FAIL). The number of differing digest bits is reported for each. **Avalanche:** 1,000
single-bit flips of the 1 KB BIN file at reproducible positions (seed 3082). For an ideal hash the count of changed bits
follows Binomial(256, 0.5): mean 128, SD 8. Individual flips vary (e.g. 116 or 123 bits), so no single test is
expected to change exactly 50 %. The avalanche experiment demonstrates expected behaviour. It does **not** prove
preimage or collision resistance.

## Known limitations

- **One machine.** Throughput depends on the CPU (SHA-NI hardware instructions), OpenSSL version, power mode
  and background load. Check SHA-NI with Sysinternals Coreinfo (`coreinfo64 -f`, look for `SHA`).
- **Small inputs (1 KB–100 KB)** are dominated by fixed costs (opening the file, Python calls), so their throughput is
  not SHA-256 speed, and their CV is higher (≈ 8–18 %) because microsecond scheduling noise is large relative to the
  measurement.
- **Warm OS cache:** after the warm-up, file reads come from RAM. Cold-disk (SSD/HDD) I/O was not measured.
- **Memory:** `tracemalloc` sees Python allocations (the read buffers), not OpenSSL's internal state (~100 bytes).
  **RSS grows with file size only because the benchmark keeps one copy of the file in RAM for the in-memory
  timing**. It is not memory used by hashing, so the report should use the traced peak for hashing memory.
- **CPU** is an average over a sampling window, not a per-call value. It is ≈ 99 % of one core for every size (single-threaded,
  compute-bound). psutil's `cpu_os_pct` under-reports on this hybrid-core laptop (37–69 %) and is not used as the main
  figure.

## Evidence / screenshots to capture

1. `python -m pytest -v tests/test_sha256.py` showing **63 passed** (include the known-vector test names).
2. `python -m benchmarks.sha256_integrity_demo`, full console output: known-answer tests all PASS (including the
   certutil cross-check), the text example digest, the **original digest (PASS)**, the **1-bit / 1-byte / appended
   digests (FAIL)** with bits changed, and the avalanche summary line.
3. The same file hashed independently: `certutil -hashfile results\integrity_demo\original_1MB.txt SHA256` and
   `certutil -hashfile results\integrity_demo\modified_1bit_1MB.txt SHA256`, matching the script output.
4. File Explorer (details view) or `dir datasets\data\BIN` showing the exact byte sizes.
5. `python -m benchmarks.benchmark_sha256` console: environment, the 24 result lines with `PASS 10/10`, the
   chunk-size table and `Digest verification failures: 0`.
6. `results\sha256_summary.csv` opened in Excel, and a few rows of `sha256_results.csv`.
7. The six PNGs in `results\graphs\`.
8. A short excerpt of `hash_file_chunked()` and `integrity_check()` for the appendix or viva.
9. Optional: Task Manager during the 50 MB run (one core busy), and the Coreinfo `SHA` line.

## Where each report value comes from

| Report item (IT23548046_SHA256_Section.docx) | Source |
|---|---|
| Table 3 environment | `sha256_environment.txt` (use the "hashlib backend" line for the OpenSSL version) + Coreinfo + storage type |
| Table 4 known-answer tests | `sha256_known_answer_tests.csv` |
| Table 5 benchmark (BIN rows) | `sha256_summary.csv`: `mean_ms`, `std_ms`, `cpu_mean_pct`, `peak_mean_MB`, `throughput_MBps`, `digest_consistency` |
| Table 6 file type at 10 MB | `sha256_summary.csv` rows `*_10MB`: mean/min/max/std/cv, `inmemory_mean_ms`, `throughput_MBps` |
| Table 7 integrity | `sha256_integrity_avalanche.csv` + avalanche line of the demo output |
| Table 8 chunk size | `sha256_chunk_size_experiment.csv` |
| Figs 3–8 | `results/graphs/sha256_time/cpu/memory/throughput/chunk_size/avalanche.png` |

**Report text to update so that it matches this code.**
- Section 2.3: BIN data is deterministic SHAKE-256, not `os.urandom`.
- Section 2.3: the functions are now in separate modules.
- Section 2.3: the reference manifest is `datasets/manifest.csv`, not `reference_manifest.csv`.
- Section 3.3: the byte case replaces a character (plus there is an appended-byte case).
- Section 3.4: CPU is measured with cycle counts on Windows, with psutil kept for comparison.
- Section 3.5: the raw file is named `sha256_results.csv`.
- Figure captions: the files are `sha256_*.png`.
- Section E: sample files go in `datasets/samples/`.

## Git workflow

```powershell
git checkout -b feature/sha256-chanuka
git add src/sha256_hash.py;                      git commit -m "Implement SHA-256 hashing, chunked file hashing and integrity verification"
git add tests/test_sha256.py;                    git commit -m "Add SHA-256 unit tests"
git add benchmarks/sha256_integrity_demo.py;     git commit -m "Add SHA-256 known-answer, integrity and avalanche demonstration"
git add benchmarks/benchmark_sha256.py;          git commit -m "Add SHA-256 benchmark with CPU, memory metrics and CSV export"
git add benchmarks/plot_sha256.py;               git commit -m "Add SHA-256 performance graphs"
git add README_SHA256.md README.md .gitignore datasets/generate_test_data.py
git commit -m "Add SHA-256 documentation"
git add results/sha256_* results/graphs/sha256_*; git commit -m "Add SHA-256 benchmark results"
git push -u origin feature/sha256-chanuka       # then open a pull request into main
```

## Likely errors and fixes

| Error | Fix |
|---|---|
| `ModuleNotFoundError: No module named 'src'` | Run from the project root with `python -m benchmarks.benchmark_sha256`, not `python benchmarks\benchmark_sha256.py` |
| `Missing dataset ... Run: python -m datasets.generate_test_data` | Generate the datasets first |
| `Activate.ps1 cannot be loaded` | `Set-ExecutionPolicy -Scope CurrentUser RemoteSigned` |
| `No module named psutil / matplotlib` | Activate the venv, then `pip install -r requirements.txt` |
| `--trials must be at least 10` | Use `--quick` for a smoke test. Report runs need ≥ 10 |
| `PermissionError` writing a CSV | Close the CSV in Excel and rerun |
| Very different numbers between runs | Plug in AC power, choose *Best performance*, close browser/sync apps, and rerun |

## Viva summary

SHA-256 (FIPS 180-4) maps any input to a 256-bit digest by padding it to 512-bit blocks and compressing each block
in 64 rounds into a 256-bit chaining value. It has no key and no inverse, so it gives integrity, not confidentiality.
The implementation uses Python's `hashlib` (OpenSSL) rather than hand-written rounds, because a vetted
implementation is correct and fast. Correctness is shown against published vectors and an independent
Windows implementation (`certutil`). Files are hashed in 64 KiB binary chunks: the digest is identical to one-shot
hashing, memory stays ≈ 0.13 MB for any file size, and the chunk-size experiment showed 64 KiB to be the fastest option.
Integrity verification recomputes the digest and compares it with a trusted reference. Every modification
(1 bit, 1 byte, appended byte) failed, and about half the digest bits changed (in our run, a mean of 128.09 over 1,000 flips vs.
ideal 128). Performance in our run: time grows linearly with size above about 1 MB, throughput levels off at about 1.7 GB/s from files
and about 2.3 GB/s in memory, CPU is ≈ 99 % of one core, and file type makes no difference at equal size. HMAC-SHA-256 is
needed for authentication, and Argon2/PBKDF2 for passwords.
