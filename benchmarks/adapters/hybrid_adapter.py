"""
Hybrid-encryption adapter: how real systems (TLS, PGP, S/MIME, cloud KMS
"envelope encryption") combine the three primitives.

Sender:   SHA-256 digest of the file -> fresh AES-256 key -> AES-GCM encrypt the
          file -> RSA-OAEP wrap (encrypt) the 32-byte AES key
Receiver: RSA-OAEP unwrap the AES key -> AES-GCM decrypt -> SHA-256 of the
          recovered file, compared with the sender's digest

Every step is timed separately so the analysis can show where the time goes.
The RSA key pair is created in setup() (untimed; RSA key generation has its
own scenario). Only available when the RSA module is present.
"""
from __future__ import annotations

from functools import partial

from benchmarks.adapters.rsa_adapter import RSAAdapter
from benchmarks.framework import HYBRID, AlgorithmAdapter, Operation
from src.aes_crypto import AESGCMCipher, generate_key, verify_decryption
from src.sha256_hash import compare_hashes, hash_bytes

AES_BITS = 256
SENDER_STEPS = ("sha256_digest", "aes_keygen", "aes_encrypt", "rsa_wrap")
RECEIVER_STEPS = ("rsa_unwrap", "aes_decrypt", "sha256_verify")
STEP_PRIMITIVE = {"sha256_digest": "SHA-256", "sha256_verify": "SHA-256",
                  "aes_keygen": "AES-GCM", "aes_encrypt": "AES-GCM", "aes_decrypt": "AES-GCM",
                  "rsa_wrap": "RSA", "rsa_unwrap": "RSA"}


class HybridAdapter(AlgorithmAdapter):
    name = "Hybrid"
    category = "hybrid"

    def __init__(self, rsa: RSAAdapter) -> None:
        super().__init__()
        self.rsa = rsa
        if not rsa.available:
            self.unavailable_reason = "needs the RSA module, which is not available (see the RSA warning)"

    @property
    def variants(self) -> tuple[str, ...]:
        return tuple(f"{v}+AES-{AES_BITS}" for v in self.rsa.variants) if self.available else ()

    def operations(self, variant: str, scenario: str) -> list[Operation]:
        if scenario != HYBRID:
            return []
        rsa = self.rsa

        def aes_encrypt(ctx, data):
            ctx["sender_cipher"] = AESGCMCipher(ctx["outputs"]["aes_keygen"])
            return partial(ctx["sender_cipher"].encrypt, data, ctx["aad"])

        def aes_decrypt(ctx, data):
            receiver = AESGCMCipher(ctx["outputs"]["rsa_unwrap"])       # key recovered via RSA
            return partial(receiver.decrypt, ctx["outputs"]["aes_encrypt"])

        return [
            Operation("sha256_digest", lambda ctx, data: partial(hash_bytes, data)),
            Operation("aes_keygen", lambda ctx, data: partial(generate_key, AES_BITS), bulk=False),
            Operation("aes_encrypt", aes_encrypt),
            Operation("rsa_wrap", lambda ctx, data: partial(rsa.encrypt, ctx["pub"], ctx["outputs"]["aes_keygen"]),
                      bulk=False),
            Operation("rsa_unwrap", lambda ctx, data: partial(rsa.decrypt, ctx["priv"], ctx["outputs"]["rsa_wrap"]),
                      bulk=False),
            Operation("aes_decrypt", aes_decrypt),
            Operation("sha256_verify", lambda ctx, data: partial(hash_bytes, ctx["outputs"]["aes_decrypt"])),
        ]

    def setup(self, variant: str, data: bytes, meta: dict) -> dict:
        rsa_variant = variant.split("+")[0]
        priv, pub = self.rsa.generate_keypair(RSAAdapter.bits(rsa_variant))
        aad = f"hybrid|{variant}|{meta.get('file_type', '')}|{meta.get('size_label', '')}".encode()
        return {"priv": priv, "pub": pub, "aad": aad}

    def verify(self, ctx: dict, data: bytes, outputs: dict) -> bool:
        return (outputs["rsa_unwrap"] == outputs["aes_keygen"]
                and verify_decryption(data, outputs["aes_decrypt"])
                and compare_hashes(outputs["sha256_verify"], outputs["sha256_digest"]))

    def self_check(self) -> str:
        return "uses the AES, SHA-256 and RSA self-checks"

    def environment(self) -> dict[str, str]:
        return {"Hybrid scenario": "SHA-256 digest + AES-256-GCM (fresh key) + RSA-OAEP key wrap; "
                                   "RSA key pair per trial, untimed"}
