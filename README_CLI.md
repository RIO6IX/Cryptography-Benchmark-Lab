# Crypto Lab CLI (`crypto_cli.py`)

One terminal front end for the whole project: give it input and get readable output, without remembering
each script's flags. The crypto code is not duplicated. The CLI calls `src/aes_crypto.py` and
`src/sha256_hash.py`, and runs the existing benchmark, demo and plot scripts unchanged.

## Start

```powershell
pip install -r requirements.txt        # adds `rich` for the coloured tables
python crypto_cli.py                   # interactive menu
```

Run it from the project root, or from anywhere with the full path to `crypto_cli.py`.

## Interactive menu

| Menu | What you can do |
|---|---|
| 1 AES-GCM | Encrypt or decrypt text (key + base64 token + optional AAD), encrypt or decrypt any file to/from `.enc`, run the tamper-detection demo, generate keys |
| 2 SHA-256 | Hash text or files (choose the chunk size), verify a file against a trusted digest, compare two files or two digests (bits differing), run the avalanche effect on your own text, compute HMAC-SHA-256, check all datasets against `manifest.csv` |
| 3 Benchmark | Benchmark your own file, text, a generated dataset or random bytes: time, SD, throughput, CPU %, peak memory, correctness for AES-128/192/256 and/or SHA-256 |
| 4 Lab scripts | Generate datasets, run pytest, AES self-test, SHA-256 integrity demo, quick or full benchmarks, plots |
| 5 Results | Show any `results/*.csv` as a table (key columns or all, with filters like `file_type=BIN,input_size=10MB`), show the `.txt` files, open the graph PNGs |
| 6 Environment | CPU, cores, RAM, OS, Python/OpenSSL versions, CPU-measurement method |

File paths can be pasted or dragged into the terminal; surrounding quotes are removed automatically.

## One-shot commands (screenshots / scripts)

```powershell
python crypto_cli.py sha256 text "IE3082 Cryptography"
python crypto_cli.py sha256 file datasets\data\TXT\1MB.txt
python crypto_cli.py sha256 verify myfile.pdf <64-hex trusted digest>     # exit code 1 on FAIL
python crypto_cli.py sha256 compare a.txt b.txt
python crypto_cli.py sha256 avalanche "hello" --bit 3
python crypto_cli.py sha256 hmac --key Jefe "what do ya want for nothing?"
python crypto_cli.py sha256 manifest

python crypto_cli.py aes encrypt "secret text" --bits 256 --aad demo --save-key demo.key
python crypto_cli.py aes decrypt <token> --key demo.key --aad demo
python crypto_cli.py aes encrypt-file photo.jpg --save-key photo.key      # -> photo.jpg.enc
python crypto_cli.py aes decrypt-file photo.jpg.enc photo_out.jpg --key photo.key
python crypto_cli.py aes tamper
python crypto_cli.py aes keygen --bits 128

python crypto_cli.py bench aes --file datasets\data\BIN\10MB.bin --trials 10
python crypto_cli.py bench sha256 --text "abc" --trials 20
python crypto_cli.py bench both --random-kb 4096

python crypto_cli.py lab datasets          # also: tests, tests-aes, tests-sha, aes-selftest, sha-demo,
python crypto_cli.py lab sha-quick         #       aes-quick, sha-quick, aes-full, sha-full, plot-aes, plot-sha
python crypto_cli.py results                                   # list result files
python crypto_cli.py results aes_summary.csv --filter key_size=AES-256 --filter file_type=BIN
python crypto_cli.py env
```

## Notes

- **Text token** = base64(nonce ‖ ciphertext ‖ tag). The AAD is not inside the token, so pass the same `--aad`
  to decrypt. A wrong key, wrong AAD or any modified byte gives *Authentication failed*, and no plaintext is returned.
- The CLI shows a key once so you can decrypt later. It never stores a key unless you ask it to save one.
  `*.key` and `*.enc` are git-ignored.
- `bench` results are for exploring your own inputs. **Report numbers must still come from the full benchmark
  CSVs** (`lab aes-full`, `lab sha-full`), which follow the documented method (warm-up, ≥10 trials, rotated key order).
- `lab aes-full` / `lab sha-full` overwrite the committed CSVs in `results/`, and the CLI asks before running them
  from the menu. `--quick` runs write to `results/quick/`.
