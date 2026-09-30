"""
SHA-256 adapter: exposes src/sha256_hash.py (SHA-256 component) to the common runner.

The timed call is hash_bytes() on the payload already in RAM - the same basis as
the AES timing (file I/O is never timed), and the same call as the
`inmemory_*` columns of sha256_summary.csv. File-based hashing (hash_file) is
characterised by benchmark_sha256.py and is not repeated here.

Correctness: the digest must equal a trusted reference - the digest recorded in
datasets/manifest.csv when the file was generated, or (for in-memory payloads
that have no manifest entry) hashlib's digest computed outside the timed region.
"""
from __future__ import annotations

import hashlib
import ssl
from functools import partial

from benchmarks.framework import SIZE_SWEEP, SMALL_PAYLOAD, AlgorithmAdapter, Operation
from src.sha256_hash import compare_hashes, hash_bytes

# FIPS 180-2 Appendix B.1 test vector
ABC_DIGEST = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"


def _hash(ctx: dict, data: bytes):
    return partial(hash_bytes, data)


class SHA256Adapter(AlgorithmAdapter):
    name = "SHA-256"
    category = "hash"

    @property
    def variants(self) -> tuple[str, ...]:
        return ("SHA-256",)

    def operations(self, variant: str, scenario: str) -> list[Operation]:
        if scenario in (SIZE_SWEEP, SMALL_PAYLOAD):
            return [Operation("hash", _hash)]
        return []

    def setup(self, variant: str, data: bytes, meta: dict) -> dict:
        ref = meta.get("reference_sha256")
        if ref:
            return {"reference": ref, "reference_source": "datasets/manifest.csv"}
        return {"reference": hashlib.sha256(data).hexdigest(), "reference_source": "hashlib (untimed)"}

    def verify(self, ctx: dict, data: bytes, outputs: dict) -> bool:
        return compare_hashes(outputs["hash"], ctx["reference"])

    def self_check(self) -> str:
        if hash_bytes(b"abc") != ABC_DIGEST:
            raise AssertionError("SHA-256('abc') does not match the FIPS 180-2 test vector")
        return "FIPS 180-2 'abc' test vector: PASS"

    def environment(self) -> dict[str, str]:
        return {"SHA-256 implementation": "src/sha256_hash.py (hashlib)",
                "hashlib backend": ssl.OPENSSL_VERSION}
