"""Unit tests for src/aes_crypto.py.  Run from the project root:  python -m pytest -v"""
import os
from dataclasses import replace

import pytest
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from src import aes_crypto
from src.aes_crypto import (NONCE_SIZE, TAG_SIZE, AESGCMCipher, AESKeySizeError,
                            AuthenticationError, EncryptedPayload, NonceReuseError,
                            decrypt_data, decrypt_file, encrypt_data, encrypt_file,
                            generate_key, generate_nonce, verify_decryption)

KEY_SIZES = [128, 192, 256]


def flip_bit(data: bytes, index: int) -> bytes:
    b = bytearray(data)
    b[index] ^= 0x01
    return bytes(b)


# ------------------------------------------------------------------ keys and nonces
@pytest.mark.parametrize("bits", KEY_SIZES)
def test_generate_key_length(bits):
    assert len(generate_key(bits)) == bits // 8


def test_keys_are_random():
    assert len({generate_key(256) for _ in range(100)}) == 100


@pytest.mark.parametrize("bad", [0, 64, 100, 127, 129, 512, -128, "128", 128.0, None, True])
def test_invalid_key_size_rejected(bad):
    with pytest.raises(AESKeySizeError):
        generate_key(bad)


@pytest.mark.parametrize("length", [0, 8, 15, 17, 31, 33, 64])
def test_invalid_key_length_rejected(length):
    with pytest.raises(AESKeySizeError):
        AESGCMCipher(os.urandom(length))


def test_non_bytes_key_rejected():
    with pytest.raises(TypeError):
        AESGCMCipher("0" * 32)


def test_nonce_is_96_bits_and_unique():
    nonces = [generate_nonce() for _ in range(10_000)]
    assert all(len(n) == NONCE_SIZE == 12 for n in nonces)
    assert len(set(nonces)) == len(nonces)


# ------------------------------------------------------------------ known answers
@pytest.mark.parametrize("bits,expected", [
    (128, "0388dace60b6a392f328c2b971b2fe78ab6e47d42cec13bdf53a67b21257bddf"),
    (192, "98e7247c07f0fe411c267e4384b0f6002ff58d80033927ab8ef4d4587514f0fb"),
    (256, "cea7403d4d606b6e074ec5d3baf39d18d0d1c8a799996bf0265b98b5d48ab919"),
])
def test_known_answer_vectors(bits, expected):
    # McGrew-Viega GCM Test Cases 2/8/14; a fixed nonce is used only because a KAT needs one.
    assert AESGCM(bytes(bits // 8)).encrypt(bytes(12), bytes(16), None).hex() == expected


# ------------------------------------------------------------------ round trips
@pytest.mark.parametrize("bits", KEY_SIZES)
def test_round_trip(bits):
    key = generate_key(bits)
    msg = b"IE3082 AES-GCM round-trip test message"
    payload = encrypt_data(key, msg, aad=b"header")
    assert payload.ciphertext_only != msg
    recovered = decrypt_data(key, payload)
    assert recovered == msg
    assert verify_decryption(msg, recovered)


@pytest.mark.parametrize("bits", KEY_SIZES)
def test_ciphertext_length_and_tag(bits):
    payload = encrypt_data(generate_key(bits), b"x" * 1000)
    assert len(payload.ciphertext) == 1000 + TAG_SIZE
    assert len(payload.tag) == 16


@pytest.mark.parametrize("bits", KEY_SIZES)
def test_empty_input(bits):
    key = generate_key(bits)
    payload = encrypt_data(key, b"")
    assert len(payload.ciphertext) == TAG_SIZE        # tag only
    assert decrypt_data(key, payload) == b""


@pytest.mark.parametrize("bits", KEY_SIZES)
def test_binary_input_all_byte_values(bits):
    key = generate_key(bits)
    msg = bytes(range(256)) * 64
    assert decrypt_data(key, encrypt_data(key, msg)) == msg


@pytest.mark.parametrize("bits", KEY_SIZES)
def test_large_input_10mb(bits):
    key = generate_key(bits)
    msg = os.urandom(10 * 1024 * 1024)
    assert verify_decryption(msg, decrypt_data(key, encrypt_data(key, msg)))


def test_same_plaintext_gives_different_ciphertexts():
    cipher = AESGCMCipher(generate_key(256))
    a, b = cipher.encrypt(b"same message"), cipher.encrypt(b"same message")
    assert a.nonce != b.nonce and a.ciphertext != b.ciphertext


def test_non_bytes_plaintext_rejected():
    with pytest.raises(TypeError):
        encrypt_data(generate_key(128), "text is not bytes")


def test_verify_decryption_detects_mismatch():
    assert not verify_decryption(b"abc", b"abd")


# ------------------------------------------------------------------ authentication
@pytest.fixture(params=KEY_SIZES)
def encrypted(request):
    key = generate_key(request.param)
    return key, encrypt_data(key, os.urandom(4096), aad=b"file-header")


def test_tampered_ciphertext_rejected(encrypted):
    key, p = encrypted
    with pytest.raises(AuthenticationError):
        decrypt_data(key, replace(p, ciphertext=flip_bit(p.ciphertext, 100)))


def test_tampered_tag_rejected(encrypted):
    key, p = encrypted
    with pytest.raises(AuthenticationError):
        decrypt_data(key, replace(p, ciphertext=flip_bit(p.ciphertext, -1)))


def test_wrong_key_rejected(encrypted):
    key, p = encrypted
    with pytest.raises(AuthenticationError):
        decrypt_data(generate_key(len(key) * 8), p)


def test_wrong_nonce_rejected(encrypted):
    key, p = encrypted
    with pytest.raises(AuthenticationError):
        decrypt_data(key, replace(p, nonce=generate_nonce()))


def test_wrong_aad_rejected(encrypted):
    key, p = encrypted
    with pytest.raises(AuthenticationError):
        decrypt_data(key, replace(p, aad=b"other-header"))


@pytest.mark.parametrize("bad", [
    EncryptedPayload(b"\x00" * 11, b"\x00" * 32),     # short nonce
    EncryptedPayload(b"\x00" * 12, b"\x00" * 15),     # shorter than a tag
])
def test_malformed_payload_rejected(bad):
    with pytest.raises(AuthenticationError):
        decrypt_data(generate_key(128), bad)


# ------------------------------------------------------------------ nonce misuse guards
def test_nonce_reuse_is_blocked(monkeypatch):
    monkeypatch.setattr(aes_crypto, "generate_nonce", lambda: b"\x00" * 12)
    cipher = AESGCMCipher(generate_key(128))
    cipher.encrypt(b"first")
    with pytest.raises(NonceReuseError):
        cipher.encrypt(b"second")


def test_message_limit_enforced():
    cipher = AESGCMCipher(generate_key(128))
    cipher.max_messages = 3
    for _ in range(3):
        cipher.encrypt(b"m")
    with pytest.raises(NonceReuseError):
        cipher.encrypt(b"m")


def test_repr_does_not_leak_key():
    key = generate_key(256)
    text = repr(AESGCMCipher(key))
    assert key.hex() not in text and "AES-256" in text


# ------------------------------------------------------------------ files
@pytest.mark.parametrize("bits", KEY_SIZES)
def test_file_round_trip(tmp_path, bits):
    key = generate_key(bits)
    src, enc, dec = tmp_path / "in.bin", tmp_path / "in.bin.enc", tmp_path / "out.bin"
    src.write_bytes(os.urandom(200_000))
    encrypt_file(key, src, enc)
    assert enc.read_bytes()[:4] == b"AGCM"
    decrypt_file(key, enc, dec)
    assert dec.read_bytes() == src.read_bytes()


def test_tampered_file_rejected_and_nothing_written(tmp_path):
    key = generate_key(256)
    src, enc, dec = tmp_path / "in.txt", tmp_path / "in.enc", tmp_path / "out.txt"
    src.write_bytes(b"confidential report " * 1000)
    encrypt_file(key, src, enc)
    enc.write_bytes(flip_bit(enc.read_bytes(), 40))
    with pytest.raises(AuthenticationError):
        decrypt_file(key, enc, dec)
    assert not dec.exists()


def test_tampered_file_header_rejected(tmp_path):
    key = generate_key(128)
    src, enc = tmp_path / "in", tmp_path / "in.enc"
    src.write_bytes(b"data")
    encrypt_file(key, src, enc)
    enc.write_bytes(enc.read_bytes()[:4] + b"\x02" + enc.read_bytes()[5:])   # change version byte
    with pytest.raises(AuthenticationError):
        decrypt_file(key, enc, tmp_path / "out")
