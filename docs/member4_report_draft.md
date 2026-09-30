<!--
Member 4 report sections (IEEE style) - Benchmarking, Integration and Comparative Analysis.

HOW TO USE
  1. Full run:  python -m benchmarks.benchmark_all   then   python -m benchmarks.analyze
  2. Open results/member4_report_filled.md: every placeholder in double curly braces is replaced with the value from the CSVs.
     results/report_values.csv lists each value with the exact CSV row/column it came from.
  3. Anything shown as **[missing: KEY]** had no data in that run (e.g. RSA before Member 2's module exists).
  4. Each sentence of the analysis states a measured value, not a prediction. Where a sentence gives a direction
     ("faster", "slower"), check it against the filled number before submitting and rephrase if the data disagrees.
  Budget: the whole group report is max 9 pages; these sections are written for about 2.5 pages incl. 3 figures.
-->

## V. Benchmarking Methodology

**Environment.** All measurements were taken in one run on a {{ENV_CPU}} ({{ENV_LOGICAL}} logical processors,
{{ENV_RAM_GB}} GB RAM), {{ENV_OS}}, {{ENV_PYTHON}}, `cryptography` {{ENV_CRYPTOGRAPHY}} ({{ENV_OPENSSL}}) for AES-GCM
and RSA, and `hashlib` ({{ENV_HASHLIB}}) for SHA-256. Power: {{ENV_POWER}}. The run started {{RUN_STARTED}} and took
{{RUN_DURATION_S}} s (`environment_combined.txt`). RSA module: {{RSA_STATUS}}.

**Framework.** Each group member's module is wrapped in a thin adapter that contains no measurement code. A single
runner times every algorithm with the same helpers (`benchmarks/measure.py`) that the AES and SHA-256 component
benchmarks use, so all results share one method (Fig. X: architecture, README_BENCHMARK.md).

**Datasets.** The shared generator produces BIN (deterministic SHAKE-256 output), TXT, PDF and JPG inputs of
1 KB – 50 MB (1 KB = 1024 B). A SHA-256 manifest lets anyone confirm the inputs are identical. The small-payload
inputs (32 B and 190 B) are SHAKE-256 bytes with a fixed seed.

**Fair comparison.** The primitives have different purposes, so four scenarios are used:
(i) a *size sweep* of AES-128/192/256-GCM and SHA-256 over all datasets;
(ii) a *small-payload head-to-head* on identical 32 B and 190 B inputs. 190 B is the RSA-2048 OAEP limit
*k* − 2*h*Len − 2 with SHA-256, so RSA can take part;
(iii) RSA *key generation*;
(iv) a *hybrid* scenario that RSA-wraps a fresh AES-256 key, encrypts the file with AES-GCM and hashes it with
SHA-256, timing each step.
RSA is excluded from the size sweep because it cannot encrypt more than one block per operation.
All timings are in-memory. File I/O is never timed.

**Procedure.** For each configuration, one warm-up run per algorithm/variant is discarded, then
{{TRIALS}} trials follow. Within a trial all algorithm/variant pairs run on the same payload in an order that
rotates by one position per trial, so slow drift (temperature, turbo, background load) is shared rather than
biasing one algorithm. Each trial uses a fresh key. Time is `perf_counter` around one call with the garbage
collector disabled. Memory is the `tracemalloc` peak of a separate call. CPU is measured in a separate
{{CPU_WINDOW_S}} s window, from Windows `QueryProcessCycleTime` cycles relative to wall time. psutil's CPU-time
counter under-reports on this hybrid-core CPU (see the AES section) and is kept only for reference. Every trial is
verified: decryption equals the input, the digest equals the manifest reference, RSA signatures verify and forged
ones are rejected. Result: {{CORRECTNESS_SUMMARY}} (`combined_summary.csv`, column `correctness`).

**Statistics.** Mean, min, max, sample SD (*n* − 1), coefficient of variation (CV = SD/mean), the 95 % confidence
interval of the mean (± *t*₀.₉₇₅,*n*−₁·SD/√*n*), and throughput = MB/mean time (1 MB = 2²⁰ B).

## VI. Comparative Analysis

*Every value below is taken from `results/combined_summary.csv` or the derived CSVs named in brackets.*

**Bulk data (size sweep, BIN, Fig. A).** At 10 MB, AES-256-GCM encrypted at {{AES256_ENCRYPT_10MB_MBPS}} MB/s
(mean {{AES256_ENCRYPT_10MB_MS}} ms ± {{AES256_ENCRYPT_10MB_CI95}} ms, 95 % CI) and decrypted at
{{AES256_DECRYPT_10MB_MBPS}} MB/s. SHA-256 hashed the same bytes at {{SHA256_HASH_10MB_MBPS}} MB/s, i.e.
{{SHA256_VS_AES256_10MB_X}}× the AES-256 encryption throughput. At 1 KB the throughputs were only
{{AES256_ENCRYPT_1KB_MBPS}} MB/s (AES-256) and {{SHA256_HASH_1KB_MBPS}} MB/s (SHA-256). Below roughly 1 MB,
fixed per-call costs (Python call, object allocation, nonce generation) dominate, so small-input throughput
does not reflect cipher speed. At 50 MB the figures were {{AES256_ENCRYPT_50MB_MBPS}} MB/s and
{{SHA256_HASH_50MB_MBPS}} MB/s.

**AES key size.** The spread of mean encryption time across AES-128/192/256 at 10 MB was
{{AES_KEYSIZE_SPREAD_ENCRYPT_10MB_PCT}} % (AES-256 vs AES-128: {{AES256_VS_AES128_10MB_PCT}} %). AES-256 performs
14 rounds against AES-128's 10, which would add at most 40 % if the rounds were the whole cost. Compare the measured
spread with the 95 % CIs in `comparative_table.csv` before calling it a difference.

**File type.** At 10 MB the time difference between the four file types was {{AES256_FILETYPE_SPREAD_10MB_PCT}} %
for AES-256 and {{SHA256_FILETYPE_SPREAD_10MB_PCT}} % for SHA-256. Both algorithms process opaque bytes, so content
is not expected to matter. This is the experimental check of that expectation.

**Small payloads (Fig. B).** On the same 190 B input, AES-256-GCM encryption took {{AES256_ENCRYPT_190B_MS}} ms,
SHA-256 took {{SHA256_HASH_190B_MS}} ms, and RSA-2048-OAEP took {{RSA2048_ENCRYPT_190B_MS}} ms to encrypt
({{RSA2048_ENCRYPT_VS_AES256_190B_X}}× AES-256) and {{RSA2048_DECRYPT_190B_MS}} ms to decrypt
({{RSA2048_DECRYPT_VS_AES256_190B_X}}× AES-256). RSA signing took {{RSA2048_SIGN_190B_MS}} ms and verification
{{RSA2048_VERIFY_190B_MS}} ms. Public-key operations (encrypt, verify) use the small exponent *e* = 65537 and
private-key operations (decrypt, sign) the full-size exponent *d*, which is why the two pairs are expected to differ
in cost. Moving from RSA-2048 to RSA-3072
multiplied decryption time by {{RSA3072_VS_RSA2048_DECRYPT_190B_X}}.

**Key generation.** An RSA-2048 key pair took {{RSA2048_KEYGEN_MS}} ms and an RSA-3072 key pair
{{RSA3072_KEYGEN_MS}} ms ({{RSA3072_VS_RSA2048_KEYGEN_X}}×), because generation searches for large random primes.
An AES key is 32 bytes from the OS CSPRNG (`aes_keygen` row, `hybrid_breakdown.csv`).

**Hybrid encryption (Fig. C).** For a 10 MB file with RSA-2048, the full sender + receiver pipeline took
{{HYB_RSA2048_10MB_TOTAL_MS}} ms. RSA key wrapping/unwrapping accounted for {{HYB_RSA2048_10MB_RSA_SHARE_PCT}} % of
it, AES-GCM for {{HYB_RSA2048_10MB_AES_SHARE_PCT}} % and SHA-256 for the rest. That is
{{HYB_RSA2048_10MB_OVERHEAD_VS_AES_PCT}} % more than AES-256-GCM encryption + decryption alone. For a 1 KB file the RSA
share was {{HYB_RSA2048_1KB_RSA_SHARE_PCT}} % (`hybrid_breakdown.csv`). The RSA cost is fixed per message, while the
AES and SHA-256 cost grows with the file.

**CPU and memory.** Every operation is single-threaded. CPU utilisation was {{AES256_ENCRYPT_10MB_CPU}} % (AES-256)
and {{SHA256_HASH_10MB_CPU}} % (SHA-256) of one logical core at 10 MB (Fig. `cmp_cpu.png`). The traced peak memory of
AES-256 encryption was {{AES256_ENCRYPT_50MB_MEM}} MB at 50 MB, because the one-shot API returns a new ciphertext
buffer of the input size. SHA-256 needed {{SHA256_HASH_50MB_MEM}} MB, because it returns only a 64-character digest
(`cmp_memory.png`).

**Stability.** {{N_HIGH_CV}} of {{N_CONFIGS}} configurations had CV > 10 % (`stability_summary.csv`). The median
CV was {{MEDIAN_CV_SMALL_PCT}} % below 1 MB and {{MEDIAN_CV_LARGE_PCT}} % at or above 1 MB. The highest was
{{MAX_CV_PCT}} % ({{MAX_CV_CONFIG}}). Microsecond-scale operations are the most exposed to scheduler noise, so their
comparisons rely on the 95 % CIs (Fig. `cmp_variance.png`).

*Suggested figures (3 max):* A = `cmp_throughput_vs_size.png`, B = `cmp_small_payload.png`,
C = `cmp_hybrid_breakdown.png`. Table: 6–8 rows from `comparative_table.csv`, e.g. AES-256 encrypt, SHA-256 hash
and RSA-2048 encrypt/decrypt at 190 B, plus AES-256 and SHA-256 at 10 MB.

## VII. Limitations

- **One machine, one run.** Absolute numbers depend on the CPU (AES-NI and SHA extensions), the OpenSSL build, the
  power mode and background load. Trends transfer between machines; absolute values do not.
- **Python overhead.** Every call crosses the Python–C boundary and allocates Python objects, which dominates
  sub-kilobyte timings. Small-payload times are therefore upper bounds on the primitive's own cost.
- **OS scheduling noise.** Warm-up, rotation, GC suspension and CIs reduce it but cannot remove it. Microsecond
  operations show the highest CV.
- **RSA input limit.** RSA-OAEP encrypts at most 190 B (RSA-2048) or 318 B (RSA-3072), so RSA is compared only on
  small payloads and inside the hybrid scheme, not over the size sweep.
- **Memory.** `tracemalloc` sees only Python allocations (buffers). OpenSSL's internal state is invisible to it.
  RSS covers the whole process, including the benchmark's own copy of the input.
- **One-shot APIs.** AES-GCM encrypts whole files held in RAM, so peak memory grows with file size. A streaming
  design would keep it constant.
- **Warm cache, no I/O.** Inputs are in RAM. Disk speed and cold caches are not measured.
- **CPU figure.** CPU is an average over a sampling window, not a per-call value, and only indicates that the
  work is single-threaded and compute-bound.

## VIII. Conclusion

The measurements support the division of labour used in practice. **AES-GCM** is the choice for bulk
confidentiality plus integrity: it reached {{AES256_ENCRYPT_10MB_MBPS}} MB/s at 10 MB with AES-256, and the choice of
AES-128 or AES-256 changed the time by only {{AES_KEYSIZE_SPREAD_ENCRYPT_10MB_PCT}} %. AES-256 is therefore a
low-cost default. **SHA-256** gives integrity against a trusted reference at {{SHA256_HASH_10MB_MBPS}} MB/s. It has
no key, so authentication needs HMAC or a signature. **RSA** provides what symmetric primitives cannot: key
transport and signatures without a shared secret. Its per-operation cost ({{RSA2048_DECRYPT_190B_MS}} ms to decrypt
190 B) and its input limit make it unsuitable for bulk data. **Hybrid encryption** therefore uses RSA once per
message to wrap a fresh AES key, AES-GCM for the data, and SHA-256 for integrity. In our measurements RSA's share of
the total was {{HYB_RSA2048_1KB_RSA_SHARE_PCT}} % at 1 KB and {{HYB_RSA2048_10MB_RSA_SHARE_PCT}} % at 10 MB. This is how TLS, PGP and cloud envelope encryption combine the primitives.
