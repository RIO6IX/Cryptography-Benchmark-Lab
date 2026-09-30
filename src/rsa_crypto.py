"""Secure RSA-OAEP encryption and RSA-PSS signatures for IE3082.

The module intentionally exposes a small API that is consumed by the shared
benchmark framework.  All private-key arithmetic and randomness are provided
by pyca/cryptography's OpenSSL backend; textbook RSA is never used.
"""
from __future__ import annotations

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

VALID_KEY_SIZES = (2048, 3072, 4096)
PUBLIC_EXPONENT = 65537
HASH_BYTES = hashes.SHA256().digest_size


def _validate_bits(bits: int) -> None:
    if isinstance(bits, bool) or not isinstance(bits, int):
        raise TypeError("RSA key size must be an integer number of bits")
    if bits not in VALID_KEY_SIZES:
        raise ValueError(f"RSA key size must be one of {VALID_KEY_SIZES}")


def _require_bytes(value: bytes, name: str) -> None:
    if not isinstance(value, bytes):
        raise TypeError(f"{name} must be bytes")


def _oaep() -> padding.OAEP:
    return padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None,
    )


def _pss() -> padding.PSS:
    return padding.PSS(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        salt_length=padding.PSS.DIGEST_LENGTH,
    )


def max_plaintext_size(bits: int) -> int:
    """Maximum OAEP-SHA-256 plaintext: k - 2*hLen - 2 bytes."""
    _validate_bits(bits)
    return bits // 8 - 2 * HASH_BYTES - 2


def generate_keypair(bits: int = 2048):
    """Return ``(private_key, public_key)`` using the OS-backed CSPRNG."""
    _validate_bits(bits)
    private_key = rsa.generate_private_key(
        public_exponent=PUBLIC_EXPONENT,
        key_size=bits,
    )
    return private_key, private_key.public_key()


def encrypt(public_key: rsa.RSAPublicKey, plaintext: bytes) -> bytes:
    """Encrypt a short message using RSA-OAEP with SHA-256."""
    _require_bytes(plaintext, "plaintext")
    limit = max_plaintext_size(public_key.key_size)
    if len(plaintext) > limit:
        raise ValueError(
            f"plaintext is {len(plaintext)} bytes; RSA-{public_key.key_size} "
            f"OAEP-SHA-256 accepts at most {limit} bytes"
        )
    return public_key.encrypt(plaintext, _oaep())


def decrypt(private_key: rsa.RSAPrivateKey, ciphertext: bytes) -> bytes:
    """Decrypt and validate an RSA-OAEP-SHA-256 ciphertext."""
    _require_bytes(ciphertext, "ciphertext")
    return private_key.decrypt(ciphertext, _oaep())


def sign(private_key: rsa.RSAPrivateKey, message: bytes) -> bytes:
    """Create an RSA-PSS signature with SHA-256."""
    _require_bytes(message, "message")
    return private_key.sign(message, _pss(), hashes.SHA256())


def verify(public_key: rsa.RSAPublicKey, message: bytes, signature: bytes) -> bool:
    """Return ``True`` only for a valid RSA-PSS/SHA-256 signature."""
    _require_bytes(message, "message")
    _require_bytes(signature, "signature")
    try:
        public_key.verify(signature, message, _pss(), hashes.SHA256())
    except InvalidSignature:
        return False
    return True
