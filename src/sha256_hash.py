"""
SHA-256 hashing and file-integrity functions (IE3082 Cryptography - SHA-256 component).

Author: G.C.I. Sampath (IT23548046)

This module contains only hashing logic; timing, CPU and memory measurement live
in benchmarks/. SHA-256 comes from Python's standard `hashlib` module, which
uses OpenSSL's implementation (including SHA hardware instructions when the CPU
has them).

Security notes (read before reusing these functions)
  * SHA-256 is a keyless, one-way hash, NOT encryption. A digest cannot be
    "decrypted"; it can only be recomputed from the data and compared.
  * A plain SHA-256 digest detects change only when the reference digest comes
    from a trusted source. Anyone who can modify the file can also compute a new
    digest. To authenticate data with a shared secret key use HMAC-SHA-256
    (`hmac_sha256` below), or use a digital signature.
  * Never store passwords as raw SHA-256. It is fast and unsalted by design;
    use a salted, slow password hash (Argon2id, scrypt or PBKDF2).
"""
from __future__ import annotations

import hashlib
import hmac
import os
import string
from dataclasses import dataclass
from pathlib import Path

DIGEST_BITS = 256
DIGEST_HEX_LEN = 64                     # 256 bits = 32 bytes = 64 hex characters

# Default read size for file hashing: 64 KiB. It is large enough that the per-call
# overhead of read() + update() is negligible, and small enough that memory
# use stays constant (about 64 KiB) regardless of file size. The chunk-size
# experiment in benchmarks/benchmark_sha256.py measures this choice.
DEFAULT_CHUNK_SIZE = 64 * 1024

_HEX = frozenset(string.hexdigits)


# --------------------------------------------------------------- hashing
def hash_bytes(data: bytes | bytearray | memoryview) -> str:
    """SHA-256 of a byte sequence, as 64 lowercase hex characters."""
    if isinstance(data, str):
        raise TypeError("hash_bytes() needs bytes; use hash_text() for str")
    if not isinstance(data, (bytes, bytearray, memoryview)):
        raise TypeError(f"hash_bytes() needs bytes, got {type(data).__name__}")
    return hashlib.sha256(data).hexdigest()


def hash_text(text: str, encoding: str = "utf-8") -> str:
    """SHA-256 of a string after encoding it to bytes (UTF-8 by default).

    The encoding is explicit because SHA-256 hashes bytes, not characters: the
    same text in UTF-8 and UTF-16 gives different digests.
    """
    if not isinstance(text, str):
        raise TypeError(f"hash_text() needs str, got {type(text).__name__}")
    return hash_bytes(text.encode(encoding))


def _check_file(path) -> Path:
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"No such file: {p}")
    if not p.is_file():                         # e.g. a directory
        raise IsADirectoryError(f"Not a regular file: {p}")
    return p


def _check_chunk_size(chunk_size) -> int:
    if isinstance(chunk_size, bool) or not isinstance(chunk_size, int) or chunk_size <= 0:
        raise ValueError(f"chunk_size must be a positive integer, got {chunk_size!r}")
    return chunk_size


def hash_file_chunked(path, chunk_size: int = DEFAULT_CHUNK_SIZE) -> str:
    """SHA-256 of a file, read in binary mode `chunk_size` bytes at a time.

    SHA-256 processes its input block by block, so feeding the file through
    update() in pieces gives exactly the same digest as hashing it in one call,
    while memory use stays about `chunk_size` bytes whatever the file size.
    """
    chunk_size = _check_chunk_size(chunk_size)
    h = hashlib.sha256()
    with open(_check_file(path), "rb") as f:
        while chunk := f.read(chunk_size):
            h.update(chunk)
    return h.hexdigest()


def hash_file(path) -> str:
    """SHA-256 of a file with the recommended settings (64 KiB chunked reads).

    This is the function other components should call.
    """
    return hash_file_chunked(path, DEFAULT_CHUNK_SIZE)


def hash_file_whole(path) -> str:
    """SHA-256 of a file read into memory in one go.

    Same digest as hash_file(), but memory grows with file size. It is kept
    only as the baseline for the chunk-size experiment; prefer hash_file().
    """
    return hash_bytes(_check_file(path).read_bytes())


# --------------------------------------------------------------- comparison / integrity
def normalise_digest(digest: str) -> str:
    """Validate a hex SHA-256 digest and return it stripped and lowercase."""
    if not isinstance(digest, str):
        raise TypeError(f"digest must be a hex string, got {type(digest).__name__}")
    d = digest.strip().lower()
    if len(d) != DIGEST_HEX_LEN or not set(d) <= _HEX:
        raise ValueError(f"not a SHA-256 hex digest (need {DIGEST_HEX_LEN} hex characters): {digest!r}")
    return d


def compare_hashes(digest_a: str, digest_b: str) -> bool:
    """True if two hex SHA-256 digests are equal (case-insensitive).

    hmac.compare_digest takes the same time wherever the first difference is.
    That is not needed for public file digests, but it is the correct habit
    because the same comparison is used for secret values such as HMAC tags.
    """
    return hmac.compare_digest(normalise_digest(digest_a), normalise_digest(digest_b))


def verify_file_hash(path, expected_digest: str, chunk_size: int = DEFAULT_CHUNK_SIZE) -> bool:
    """True if the file's SHA-256 matches the trusted reference digest."""
    expected = normalise_digest(expected_digest)        # reject a malformed reference early
    return compare_hashes(hash_file_chunked(path, chunk_size), expected)


@dataclass(frozen=True)
class IntegrityResult:
    path: str
    expected: str
    actual: str
    match: bool

    @property
    def status(self) -> str:
        return "PASS" if self.match else "FAIL"

    @property
    def differing_bits(self) -> int:
        return hamming_distance(self.expected, self.actual)


def integrity_check(path, expected_digest: str, chunk_size: int = DEFAULT_CHUNK_SIZE) -> IntegrityResult:
    """Recompute a file's digest and report it together with the reference.

    Unlike verify_file_hash(), this returns both digests so the result can be
    shown or logged (e.g. the original vs modified file demonstration).
    """
    expected = normalise_digest(expected_digest)
    actual = hash_file_chunked(path, chunk_size)
    return IntegrityResult(os.fspath(path), expected, actual, compare_hashes(actual, expected))


def hamming_distance(digest_a: str, digest_b: str) -> int:
    """Number of bit positions (of 256) in which two hex digests differ."""
    a, b = int(normalise_digest(digest_a), 16), int(normalise_digest(digest_b), 16)
    return (a ^ b).bit_count()


# --------------------------------------------------------------- keyed hashing
def hmac_sha256(key: bytes, data: bytes) -> str:
    """HMAC-SHA-256 tag of `data` under a secret `key` (RFC 2104 / FIPS 198-1).

    Contrast with SHA-256: SHA-256(data) can be computed by anyone, so it only
    detects change against a trusted reference. HMAC needs the secret key, so a
    matching tag also shows the data came from a key holder. HMAC is not
    SHA-256(key || data), which would be open to length-extension forgery.
    """
    if not isinstance(key, (bytes, bytearray)) or not isinstance(data, (bytes, bytearray, memoryview)):
        raise TypeError("hmac_sha256() needs bytes for key and data")
    return hmac.new(key, data, hashlib.sha256).hexdigest()
