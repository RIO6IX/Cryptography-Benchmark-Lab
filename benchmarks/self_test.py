"""
Correctness checks run before every benchmark; results go to correctness_tests.csv.

    python -m benchmarks.self_test

These overlap with tests/test_aes.py on purpose: pytest is the developer test
suite, while this module produces a CSV record for the report (Table 5) from the
same machine and run as the performance data.
"""
from __future__ import annotations

import csv
import os
import sys
from dataclasses import replace
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from src.aes_crypto import (VALID_KEY_SIZES, AESGCMCipher, AESKeySizeError,
                            AuthenticationError, generate_key, generate_nonce,
                            verify_decryption)

# Known-answer tests from McGrew & Viega, "The Galois/Counter Mode of Operation
# (GCM)": Test Cases 2, 8 and 14 (all-zero key, all-zero 96-bit IV, one zero block).
# A fixed nonce is used ONLY here, because a KAT needs a fixed input.
KATS = {
    128: "0388dace60b6a392f328c2b971b2fe78" "ab6e47d42cec13bdf53a67b21257bddf",
    192: "98e7247c07f0fe411c267e4384b0f600" "2ff58d80033927ab8ef4d4587514f0fb",
    256: "cea7403d4d606b6e074ec5d3baf39d18" "d0d1c8a799996bf0265b98b5d48ab919",
}


def _flip(data: bytes, index: int) -> bytes:
    b = bytearray(data)
    b[index] ^= 0x01
    return bytes(b)


def _rejected(cipher: AESGCMCipher, payload) -> bool:
    try:
        cipher.decrypt(payload)
    except AuthenticationError:
        return True
    return False


def run_self_tests(out_csv: Path | None = None, verbose: bool = True) -> bool:
    rows = []

    def record(test, bits, expected, ok):
        rows.append([test, f"AES-{bits}" if bits else "-", expected, "PASS" if ok else "FAIL"])

    for bits in VALID_KEY_SIZES:
        kat = AESGCM(bytes(bits // 8)).encrypt(bytes(12), bytes(16), None).hex()
        record("Known-answer test (McGrew-Viega GCM vector)", bits, "Output matches vector", kat == KATS[bits])

        key = generate_key(bits)
        cipher = AESGCMCipher(key)
        msg = os.urandom(4096)
        aad = f"AES-{bits}".encode()
        p = cipher.encrypt(msg, aad)
        record("Encrypt-decrypt round trip (4 KB)", bits, "Identical plaintext",
               verify_decryption(msg, cipher.decrypt(p)))
        record("Empty plaintext round trip", bits, "Identical (empty) plaintext",
               cipher.decrypt(cipher.encrypt(b"", aad)) == b"")
        record("Ciphertext length = plaintext + 16-byte tag", bits, "4112 bytes",
               len(p.ciphertext) == len(msg) + 16)

        tamper_cases = {
            "Modified ciphertext (1 bit)": (cipher, replace(p, ciphertext=_flip(p.ciphertext, 0))),
            "Modified tag (1 bit)": (cipher, replace(p, ciphertext=_flip(p.ciphertext, -1))),
            "Wrong key": (AESGCMCipher(generate_key(bits)), p),
            "Wrong nonce": (cipher, replace(p, nonce=generate_nonce())),
            "Wrong AAD": (cipher, replace(p, aad=b"other")),
            "Truncated ciphertext": (cipher, replace(p, ciphertext=p.ciphertext[:-1])),
        }
        for name, (c, bad) in tamper_cases.items():
            record(name, bits, "Rejected (AuthenticationError)", _rejected(c, bad))

    for bad_size in (0, 64, 100, 512, "128", True):
        try:
            generate_key(bad_size)
            ok = False
        except AESKeySizeError:
            ok = True
        record(f"Invalid key size {bad_size!r} rejected", None, "AESKeySizeError", ok)

    nonces = {AESGCMCipher(generate_key(128)).encrypt(b"x").nonce for _ in range(10000)}
    record("10,000 nonces are unique and 96-bit", None, "10000 distinct 12-byte nonces",
           len(nonces) == 10000 and all(len(n) == 12 for n in nonces))

    if out_csv:
        out_csv.parent.mkdir(parents=True, exist_ok=True)
        with open(out_csv, "w", newline="") as f:
            w = csv.writer(f)
            w.writerow(["test", "key_size", "expected", "result"])
            w.writerows(rows)
    if verbose:
        for r in rows:
            print(f"  {r[0]:<46} {r[1]:<8} {r[3]}")
    return all(r[3] == "PASS" for r in rows)


if __name__ == "__main__":
    out = Path(__file__).resolve().parent.parent / "results" / "correctness_tests.csv"
    ok = run_self_tests(out)
    print(f"\n{'ALL TESTS PASSED' if ok else 'SOME TESTS FAILED'} - written to {out}")
    sys.exit(0 if ok else 1)
