"""
AES-GCM authenticated encryption (IE3082 Cryptography - AES component).

Author : P.D.S. Dhananjana (IT23777590)

This module contains only the cryptographic implementation. It has no timing
or measurement code, so it can be reused by the rest of the group project.

Design decisions
----------------
* Mode: AES-GCM (NIST SP 800-38D), an AEAD mode. ECB is never used.
* Keys: 128, 192 or 256 bits from the operating-system CSPRNG
  (AESGCM.generate_key -> os.urandom). Keys are never hard-coded or logged.
* Nonce: 96 bits from os.urandom, fresh for every message.
* Tag: full 128-bit tag (the library default), appended to the ciphertext.
* AESGCMCipher refuses to reuse a nonce under its key and refuses to encrypt
  more than 2**32 messages under one key (the SP 800-38D limit for random
  96-bit nonces).
* Any tag failure raises AuthenticationError and no plaintext is returned.
"""
from __future__ import annotations

import hmac
import os
from dataclasses import dataclass
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

VALID_KEY_SIZES = (128, 192, 256)    # bits
NONCE_SIZE = 12                      # bytes (96-bit nonce, SP 800-38D recommendation)
TAG_SIZE = 16                        # bytes (128-bit tag)
MAX_MESSAGES_PER_KEY = 2**32         # SP 800-38D limit for random nonces

# Encrypted file layout: MAGIC | VERSION | nonce | ciphertext || tag
# MAGIC + VERSION are passed as AAD, so the header is authenticated as well.
FILE_MAGIC = b"AGCM"
FILE_VERSION = b"\x01"
FILE_HEADER = FILE_MAGIC + FILE_VERSION


class AESKeySizeError(ValueError):
    """Raised for a key size other than 128, 192 or 256 bits."""


class AuthenticationError(Exception):
    """Raised when GCM tag verification fails (tampered data, wrong key/nonce/AAD)."""


class NonceReuseError(RuntimeError):
    """Raised if a nonce would be repeated under the same key."""


# --------------------------------------------------------------- keys and nonces
def validate_key_size(key_size: int) -> int:
    # bool is a subclass of int, so it is rejected explicitly
    if isinstance(key_size, bool) or not isinstance(key_size, int) or key_size not in VALID_KEY_SIZES:
        raise AESKeySizeError(f"AES key size must be one of {VALID_KEY_SIZES} bits, got {key_size!r}")
    return key_size


def generate_key(key_size: int) -> bytes:
    """Return a new random AES key of 128, 192 or 256 bits from the OS CSPRNG."""
    return AESGCM.generate_key(bit_length=validate_key_size(key_size))


def generate_nonce() -> bytes:
    """Return a fresh 96-bit nonce from the OS CSPRNG."""
    return os.urandom(NONCE_SIZE)


# --------------------------------------------------------------- encrypted payload
@dataclass(frozen=True)
class EncryptedPayload:
    """Everything the receiver needs except the key. The nonce is not secret."""
    nonce: bytes
    ciphertext: bytes          # ciphertext with the 16-byte tag appended
    aad: bytes = b""

    @property
    def tag(self) -> bytes:
        return self.ciphertext[-TAG_SIZE:]

    @property
    def ciphertext_only(self) -> bytes:
        return self.ciphertext[:-TAG_SIZE]


# --------------------------------------------------------------- cipher object
class AESGCMCipher:
    """AES-GCM bound to one key, with nonce-uniqueness enforcement.

    Use one instance for all messages encrypted under the same key, so that
    the nonce guard and the message counter cover every message.
    """

    def __init__(self, key: bytes):
        if not isinstance(key, (bytes, bytearray)):
            raise TypeError("key must be bytes")
        if len(key) * 8 not in VALID_KEY_SIZES:
            raise AESKeySizeError(f"AES key must be 16, 24 or 32 bytes, got {len(key)}")
        self._aead = AESGCM(bytes(key))
        self._key_size = len(key) * 8
        self._used_nonces: set[bytes] = set()
        self._messages = 0
        self.max_messages = MAX_MESSAGES_PER_KEY

    @property
    def key_size(self) -> int:
        return self._key_size

    @property
    def messages_encrypted(self) -> int:
        return self._messages

    def __repr__(self) -> str:       # never show key material
        return f"AESGCMCipher(AES-{self._key_size}, messages={self._messages})"

    def encrypt(self, plaintext: bytes, aad: bytes = b"") -> EncryptedPayload:
        if self._messages >= self.max_messages:
            raise NonceReuseError("Message limit for this key reached - rotate the key")
        nonce = generate_nonce()
        if nonce in self._used_nonces:
            raise NonceReuseError("Nonce reuse detected - encryption aborted")
        self._used_nonces.add(nonce)
        self._messages += 1
        return EncryptedPayload(nonce, self._aead.encrypt(nonce, plaintext, aad), aad)

    def decrypt(self, payload: EncryptedPayload) -> bytes:
        if len(payload.nonce) != NONCE_SIZE or len(payload.ciphertext) < TAG_SIZE:
            raise AuthenticationError("Malformed payload")
        try:
            return self._aead.decrypt(payload.nonce, payload.ciphertext, payload.aad)
        except InvalidTag:
            raise AuthenticationError("Authentication failed - data rejected") from None


# --------------------------------------------------------------- one-shot helpers
def encrypt_data(key: bytes, plaintext: bytes, aad: bytes = b"") -> EncryptedPayload:
    """Encrypt one message. For many messages under one key, reuse an AESGCMCipher
    so the nonce guard and message limit apply across all of them."""
    return AESGCMCipher(key).encrypt(plaintext, aad)


def decrypt_data(key: bytes, payload: EncryptedPayload) -> bytes:
    """Verify the tag and decrypt. Raises AuthenticationError on any tampering."""
    return AESGCMCipher(key).decrypt(payload)


def verify_decryption(original: bytes, recovered: bytes) -> bool:
    """True if the recovered plaintext is byte-for-byte identical to the original."""
    return hmac.compare_digest(original, recovered)


# --------------------------------------------------------------- files
def encrypt_file(key: bytes, src: str | Path, dst: str | Path) -> int:
    """Encrypt the file at src into dst. Returns the number of bytes written.
    The whole file is held in memory (one-shot API, suitable up to a few hundred MB)."""
    payload = encrypt_data(key, Path(src).read_bytes(), aad=FILE_HEADER)
    blob = FILE_HEADER + payload.nonce + payload.ciphertext
    Path(dst).write_bytes(blob)
    return len(blob)


def decrypt_file(key: bytes, src: str | Path, dst: str | Path) -> int:
    """Decrypt a file produced by encrypt_file. Nothing is written if authentication fails."""
    blob = Path(src).read_bytes()
    hlen = len(FILE_HEADER)
    if len(blob) < hlen + NONCE_SIZE + TAG_SIZE or blob[:len(FILE_MAGIC)] != FILE_MAGIC:
        raise AuthenticationError("Not an AES-GCM file produced by encrypt_file")
    payload = EncryptedPayload(nonce=blob[hlen:hlen + NONCE_SIZE],
                               ciphertext=blob[hlen + NONCE_SIZE:],
                               aad=blob[:hlen])
    plaintext = decrypt_data(key, payload)
    Path(dst).write_bytes(plaintext)
    return len(plaintext)
