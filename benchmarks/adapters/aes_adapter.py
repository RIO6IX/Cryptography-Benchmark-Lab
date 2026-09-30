"""
AES-GCM adapter: exposes src/aes_crypto.py (AES component) to the common runner.

Timed calls are exactly the ones benchmark_aes.py times: AESGCMCipher.encrypt()
(including nonce generation and the nonce-reuse check) and AESGCMCipher.decrypt()
(including tag verification). A new CSPRNG key is generated per trial, outside
the timed region.
"""
from __future__ import annotations

from functools import partial

from benchmarks.framework import SIZE_SWEEP, SMALL_PAYLOAD, AlgorithmAdapter, Operation
from src.aes_crypto import (TAG_SIZE, VALID_KEY_SIZES, AESGCMCipher, AuthenticationError,
                            generate_key, verify_decryption)


def _encrypt(ctx: dict, data: bytes):
    return partial(ctx["cipher"].encrypt, data, ctx["aad"])


def _decrypt(ctx: dict, data: bytes):
    return partial(ctx["cipher"].decrypt, ctx["outputs"]["encrypt"])


class AESAdapter(AlgorithmAdapter):
    name = "AES-GCM"
    category = "symmetric"

    @property
    def variants(self) -> tuple[str, ...]:
        return tuple(f"AES-{bits}" for bits in VALID_KEY_SIZES)

    def operations(self, variant: str, scenario: str) -> list[Operation]:
        if scenario in (SIZE_SWEEP, SMALL_PAYLOAD):
            return [Operation("encrypt", _encrypt), Operation("decrypt", _decrypt)]
        return []

    def setup(self, variant: str, data: bytes, meta: dict) -> dict:
        bits = int(variant.split("-")[1])
        # same AAD pattern as benchmark_aes: binds key size, file type and size
        aad = f"{variant}|{meta.get('file_type', '')}|{meta.get('size_label', '')}".encode()
        return {"cipher": AESGCMCipher(generate_key(bits)), "aad": aad}

    def verify(self, ctx: dict, data: bytes, outputs: dict) -> bool:
        payload = outputs["encrypt"]
        return (len(payload.ciphertext) == len(data) + TAG_SIZE
                and verify_decryption(data, outputs["decrypt"]))

    def self_check(self) -> str:
        for bits in VALID_KEY_SIZES:
            cipher = AESGCMCipher(generate_key(bits))
            msg = b"IE3082 member 4 self-check"
            payload = cipher.encrypt(msg, b"aad")
            if cipher.decrypt(payload) != msg:
                raise AssertionError(f"AES-{bits} round trip failed")
            tampered = type(payload)(payload.nonce, bytes([payload.ciphertext[0] ^ 1]) + payload.ciphertext[1:],
                                     payload.aad)
            try:
                cipher.decrypt(tampered)
            except AuthenticationError:
                continue
            raise AssertionError(f"AES-{bits} accepted a tampered ciphertext")
        return "round trip + tamper rejection for AES-128/192/256: PASS"

    def environment(self) -> dict[str, str]:
        return {"AES implementation": "src/aes_crypto.py (AES-GCM, cryptography/OpenSSL, 96-bit nonce, 128-bit tag)"}
