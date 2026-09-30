"""
RSA adapter: exposes the RSA contributor's component to the common runner.

RSA itself is NOT implemented here. The adapter looks for the RSA module and
plugs it in automatically once it exists; until then it reports itself as
unavailable and the pipeline runs AES-GCM and SHA-256 only.

Module lookup (first one that exists): src/rsa_crypto.py, src/rsa_oaep.py,
src/rsa_cipher.py, src/rsa.py

Expected functions (the first matching name of each role is used):
  key generation  generate_keypair(bits) -> (private_key, public_key)
                  (a private-key object with .public_key() is also accepted)
                  aliases: generate_key_pair, generate_keys, generate_rsa_keypair, generate_rsa_keys
  encryption      encrypt(public_key, plaintext: bytes) -> bytes          RSA-OAEP
                  aliases: rsa_encrypt, encrypt_data, oaep_encrypt, encrypt_message
  decryption      decrypt(private_key, ciphertext: bytes) -> bytes
                  aliases: rsa_decrypt, decrypt_data, oaep_decrypt, decrypt_message
  signing         sign(private_key, message: bytes) -> bytes              optional
                  aliases: rsa_sign, sign_data, sign_message
  verification    verify(public_key, message, signature) -> bool          optional
                  (returning None and raising on a bad signature is also accepted)
                  aliases: rsa_verify, verify_signature, verify_data, verify_message
Optional module attributes:
  VALID_KEY_SIZES (or KEY_SIZES / SUPPORTED_KEY_SIZES), default (2048, 3072)
  max_plaintext_size(bits) (or max_message_size / max_input_size), default
  k - 2*32 - 2 bytes, the RSA-OAEP limit with SHA-256 (190 B for RSA-2048)

If the module exists but does not match this contract, the adapter is skipped
with a message that says which function is missing or which check failed.
"""
from __future__ import annotations

import importlib
import os
from functools import partial
from types import ModuleType
from typing import Any, Callable

from benchmarks.framework import KEYGEN, SMALL_PAYLOAD, AlgorithmAdapter, Operation

MODULE_CANDIDATES = ("src.rsa_crypto", "src.rsa_oaep", "src.rsa_cipher", "src.rsa")
ROLES: dict[str, tuple[str, ...]] = {
    "keygen": ("generate_keypair", "generate_key_pair", "generate_keys", "generate_rsa_keypair",
               "generate_rsa_keys"),
    "encrypt": ("encrypt", "rsa_encrypt", "encrypt_data", "oaep_encrypt", "encrypt_message"),
    "decrypt": ("decrypt", "rsa_decrypt", "decrypt_data", "oaep_decrypt", "decrypt_message"),
    "sign": ("sign", "rsa_sign", "sign_data", "sign_message"),
    "verify": ("verify", "rsa_verify", "verify_signature", "verify_data", "verify_message"),
}
REQUIRED_ROLES = ("keygen", "encrypt", "decrypt")
KEY_SIZE_ATTRS = ("VALID_KEY_SIZES", "KEY_SIZES", "SUPPORTED_KEY_SIZES")
LIMIT_FUNCS = ("max_plaintext_size", "max_message_size", "max_input_size")
DEFAULT_KEY_SIZES = (2048, 3072)
OAEP_HASH_BYTES = 32          # SHA-256


def oaep_limit(bits: int, hash_bytes: int = OAEP_HASH_BYTES) -> int:
    """Largest RSA-OAEP plaintext: k - 2*hLen - 2 bytes (RFC 8017, section 7.1.1)."""
    return bits // 8 - 2 * hash_bytes - 2


def find_module(candidates: tuple[str, ...] = MODULE_CANDIDATES) -> tuple[ModuleType | None, str]:
    """Import the first RSA module that exists. Returns (module, name) or (None, reason)."""
    for name in candidates:
        try:
            return importlib.import_module(name), name
        except ModuleNotFoundError as e:
            if e.name == name:                      # this candidate does not exist - try the next one
                continue
            return None, f"{name} exists but failed to import: {e}"
        except Exception as e:                      # syntax error etc. inside the RSA module
            return None, f"{name} exists but failed to import: {type(e).__name__}: {e}"
    paths = ", ".join("src/" + c.split(".", 1)[1] + ".py" for c in candidates)
    return None, (f"no RSA module found (looked for {paths}). RSA benchmarks and the hybrid scenario "
                  "are skipped; AES-GCM and SHA-256 still run")


def split_keypair(result: Any) -> tuple[Any, Any]:
    """Accept (private, public), an object with .private_key/.public_key, or a private key object."""
    if isinstance(result, (tuple, list)) and len(result) == 2:
        return result[0], result[1]
    priv = getattr(result, "private_key", None)
    pub = getattr(result, "public_key", None)
    if priv is not None and pub is not None and not callable(pub):
        return priv, pub
    if callable(pub):
        return result, pub()
    raise TypeError("key generation must return (private_key, public_key) or a private key with .public_key()")


class RSAAdapter(AlgorithmAdapter):
    name = "RSA"
    category = "asymmetric"

    def __init__(self, module: ModuleType | None = None, module_name: str | None = None,
                 candidates: tuple[str, ...] = MODULE_CANDIDATES) -> None:
        super().__init__()
        self.module_name = module_name
        self.fns: dict[str, Callable] = {}
        self.key_sizes: tuple[int, ...] = ()
        if module is None:
            module, found = find_module(candidates)
            if module is None:
                self.unavailable_reason = found
                return
            self.module_name = found
        self.module = module
        self.module_name = self.module_name or getattr(module, "__name__", "rsa module")
        for role, names in ROLES.items():
            fn = next((getattr(module, n) for n in names if callable(getattr(module, n, None))), None)
            if fn is not None:
                self.fns[role] = fn
        missing = [r for r in REQUIRED_ROLES if r not in self.fns]
        if missing:
            wanted = "; ".join(f"{r}: one of {', '.join(ROLES[r])}" for r in missing)
            self.unavailable_reason = (f"{self.module_name} does not match the adapter contract "
                                       f"(missing {wanted}). See benchmarks/adapters/rsa_adapter.py")
            return
        sizes = next((getattr(module, a) for a in KEY_SIZE_ATTRS if hasattr(module, a)), DEFAULT_KEY_SIZES)
        self.key_sizes = tuple(sorted(int(b) for b in sizes))
        self._limit_fn = next((getattr(module, n) for n in LIMIT_FUNCS if callable(getattr(module, n, None))), None)

    # ------------------------------------------------ thin wrappers (used by the hybrid adapter too)
    def generate_keypair(self, bits: int) -> tuple[Any, Any]:
        return split_keypair(self.fns["keygen"](bits))

    def encrypt(self, public_key, data: bytes) -> bytes:
        return self.fns["encrypt"](public_key, data)

    def decrypt(self, private_key, ciphertext: bytes) -> bytes:
        return self.fns["decrypt"](private_key, ciphertext)

    def signature_valid(self, public_key, message: bytes, signature: bytes) -> bool:
        try:
            result = self.fns["verify"](public_key, message, signature)
        except Exception:
            return False
        return result is None or bool(result)

    @property
    def can_sign(self) -> bool:
        return "sign" in self.fns and "verify" in self.fns

    @staticmethod
    def bits(variant: str) -> int:
        return int(variant.split("-")[1])

    # ------------------------------------------------ adapter interface
    @property
    def variants(self) -> tuple[str, ...]:
        return tuple(f"RSA-{b}" for b in self.key_sizes) if self.available else ()

    def operations(self, variant: str, scenario: str) -> list[Operation]:
        if scenario == KEYGEN:
            return [Operation("keygen", lambda ctx, data: partial(self.fns["keygen"], ctx["bits"]), bulk=False)]
        if scenario != SMALL_PAYLOAD:
            return []                         # RSA is only benchmarked within its input limit
        ops = [Operation("encrypt", lambda ctx, data: partial(self.encrypt, ctx["pub"], data), size_limited=True),
               Operation("decrypt", lambda ctx, data: partial(self.decrypt, ctx["priv"], ctx["outputs"]["encrypt"]),
                         size_limited=True)]
        if self.can_sign:
            ops += [Operation("sign", lambda ctx, data: partial(self.fns["sign"], ctx["priv"], data)),
                    Operation("verify", lambda ctx, data: partial(self.fns["verify"], ctx["pub"], data,
                                                                  ctx["outputs"]["sign"]))]
        return ops

    def max_input_size(self, variant: str) -> int | None:
        bits = self.bits(variant)
        if self._limit_fn is not None:
            return int(self._limit_fn(bits))
        return oaep_limit(bits)

    def setup(self, variant: str, data: bytes, meta: dict) -> dict:
        ctx = {"bits": self.bits(variant)}
        if meta.get("scenario") != KEYGEN:
            # fresh key pair per trial, like the fresh AES key per trial; key generation is timed separately
            ctx["priv"], ctx["pub"] = self.generate_keypair(ctx["bits"])
        return ctx

    def verify(self, ctx: dict, data: bytes, outputs: dict) -> bool:
        ok = True
        if "keygen" in outputs:
            priv, pub = split_keypair(outputs["keygen"])
            size = getattr(priv, "key_size", ctx["bits"])
            probe = b"keygen check"
            ok &= size == ctx["bits"] and self.decrypt(priv, self.encrypt(pub, probe)) == probe
        if "decrypt" in outputs:
            ok &= outputs["decrypt"] == data and len(outputs["encrypt"]) == ctx["bits"] // 8
        if "sign" in outputs:
            sig = outputs["sign"]
            ok &= outputs["verify"] is None or bool(outputs["verify"])
            tampered = bytes([sig[0] ^ 1]) + sig[1:]
            ok &= not self.signature_valid(ctx["pub"], data, tampered)      # a forged signature must fail
        return bool(ok)

    def self_check(self) -> str:
        if not self.available:
            raise RuntimeError(self.unavailable_reason)
        bits = self.key_sizes[0]
        priv, pub = self.generate_keypair(bits)
        msg = os.urandom(32)
        if self.decrypt(priv, self.encrypt(pub, msg)) != msg:
            raise AssertionError(f"RSA-{bits} encrypt/decrypt round trip failed")
        limit = self.max_input_size(f"RSA-{bits}")
        if limit is None or limit < 32:
            raise AssertionError(f"RSA-{bits} input limit {limit} is too small to wrap an AES-256 key")
        checks = f"RSA-{bits} round trip: PASS"
        if self.can_sign:
            sig = self.fns["sign"](priv, msg)
            if not self.signature_valid(pub, msg, sig) or self.signature_valid(pub, msg + b"x", sig):
                raise AssertionError(f"RSA-{bits} sign/verify check failed")
            checks += "; sign/verify + forged-message rejection: PASS"
        return checks

    def environment(self) -> dict[str, str]:
        if not self.available:
            return {"RSA module": f"not benchmarked - {self.unavailable_reason}"}
        mod_file = getattr(self.module, "__file__", "") or ""
        limits = ", ".join(f"RSA-{b}: {self.max_input_size(f'RSA-{b}')} B" for b in self.key_sizes)
        return {"RSA module": f"{self.module_name} ({os.path.basename(mod_file)})",
                "RSA functions used": ", ".join(f"{r}={f.__name__}" for r, f in self.fns.items()),
                "RSA key sizes": list(self.key_sizes),
                "RSA-OAEP max plaintext": limits}
