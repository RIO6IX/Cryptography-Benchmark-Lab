"""Correctness and misuse tests for the RSA assignment component."""
import os

import pytest

from src.rsa_crypto import (
    VALID_KEY_SIZES,
    decrypt,
    encrypt,
    generate_keypair,
    max_plaintext_size,
    sign,
    verify,
)


@pytest.fixture(scope="module", params=VALID_KEY_SIZES)
def keypair(request):
    return request.param, generate_keypair(request.param)


def test_supported_key_sizes_and_public_exponent(keypair):
    bits, (private_key, public_key) = keypair
    assert private_key.key_size == public_key.key_size == bits
    assert public_key.public_numbers().e == 65537


def test_oaep_round_trip_and_randomisation(keypair):
    _, (private_key, public_key) = keypair
    message = os.urandom(32)
    first = encrypt(public_key, message)
    second = encrypt(public_key, message)
    assert first != second
    assert decrypt(private_key, first) == message
    assert decrypt(private_key, second) == message


def test_oaep_maximum_length_and_oversize_rejection(keypair):
    bits, (private_key, public_key) = keypair
    maximum = os.urandom(max_plaintext_size(bits))
    assert decrypt(private_key, encrypt(public_key, maximum)) == maximum
    with pytest.raises(ValueError):
        encrypt(public_key, maximum + b"x")


def test_tampered_ciphertext_is_rejected(keypair):
    _, (private_key, public_key) = keypair
    ciphertext = bytearray(encrypt(public_key, b"session key"))
    ciphertext[-1] ^= 1
    with pytest.raises(ValueError):
        decrypt(private_key, bytes(ciphertext))


def test_wrong_private_key_is_rejected(keypair):
    bits, (_, public_key) = keypair
    wrong_private, _ = generate_keypair(bits)
    with pytest.raises(ValueError):
        decrypt(wrong_private, encrypt(public_key, b"session key"))


def test_pss_signature_and_modified_message(keypair):
    _, (private_key, public_key) = keypair
    message = os.urandom(1024)
    signature = sign(private_key, message)
    assert verify(public_key, message, signature)
    assert not verify(public_key, message + b"x", signature)


@pytest.mark.parametrize("bad", [1024, 1536, 8192, 0, -1])
def test_unsupported_key_sizes_are_rejected(bad):
    with pytest.raises(ValueError):
        generate_keypair(bad)


@pytest.mark.parametrize("bad", ["2048", 2048.0, None, True])
def test_non_integer_key_sizes_are_rejected(bad):
    with pytest.raises(TypeError):
        generate_keypair(bad)


def test_plaintext_must_be_bytes(keypair):
    _, (_, public_key) = keypair
    with pytest.raises(TypeError):
        encrypt(public_key, "not bytes")
