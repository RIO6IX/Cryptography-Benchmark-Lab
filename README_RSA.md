# RSA / Asymmetric Cryptography Component

This component implements and evaluates RSA-OAEP encryption and RSA-PSS
signatures for the IE3082 group assignment. It integrates with the repository's
shared benchmark runner and hybrid RSA + AES-GCM workflow.

## Security choices

- RSA keys: 2048, 3072 and 4096 bits
- Public exponent: 65537
- Encryption: OAEP with SHA-256 for both OAEP and MGF1
- Signatures: PSS with SHA-256 and digest-length salt
- Randomness and private-key arithmetic: pyca/cryptography via OpenSSL
- Textbook RSA, ECB and PKCS #1 v1.5 encryption are not used

RSA-OAEP is deliberately limited to short inputs. With SHA-256 the maximum
plaintext sizes are 190, 318 and 446 bytes for RSA-2048, RSA-3072 and RSA-4096.
Large files must use hybrid encryption: AES-GCM encrypts the data and RSA-OAEP
wraps only the 32-byte AES-256 session key.

## Files

- `src/rsa_crypto.py` - reusable RSA-OAEP/PSS implementation
- `tests/test_rsa.py` - round-trip, limit, tamper, wrong-key and signature tests
- `results/rsa_raw_trials.csv` - ten measured trials per operation/key size
- `results/graphs/rsa_performance.png` - operation time against RSA key size
- `docs/IE3082_Final_Group_Report_RSA_filled.docx` - report with the RSA material integrated

## Run and verify

```powershell
pip install -r requirements.txt
python -m pytest tests/test_rsa.py -v
python -m benchmarks.benchmark_all --quick
python -m benchmarks.benchmark_all
python -m benchmarks.analyze
```

The full shared benchmark measures RSA key generation, OAEP encryption and
decryption, PSS signing and verification, CPU usage, Python peak memory, and the
hybrid workflow. It discards a warm-up and records ten measured trials.

The checked-in RSA CSV and graph were produced by the dedicated benchmark in
the assignment `Final` folder. Absolute timings depend on the test machine, so
rerun the shared benchmark on the group machine before using numbers in the
final report.
