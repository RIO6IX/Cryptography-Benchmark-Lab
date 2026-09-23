"""
Tests for src/sha256_hash.py.  Run with:  python -m pytest -v tests/test_sha256.py

Expected digests are published values (FIPS 180-2 Appendix B / RFC 6234, RFC 4231),
not values produced by this code.
"""
import hashlib
import os

import pytest

from src.sha256_hash import (DEFAULT_CHUNK_SIZE, DIGEST_HEX_LEN, IntegrityResult, compare_hashes,
                             hamming_distance, hash_bytes, hash_file, hash_file_chunked,
                             hash_file_whole, hash_text, hmac_sha256, integrity_check,
                             normalise_digest, verify_file_hash)

EMPTY = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
ABC = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
MSG_448 = b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
MSG_448_HASH = "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
MSG_896 = (b"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmno"
           b"ijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu")
MSG_896_HASH = "cf5b16a778af8380036ce59e7b0492370b249b11e8f07a51afac45037afee9d1"
MILLION_A_HASH = "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"
FOX = "The quick brown fox jumps over the lazy dog"
FOX_HASH = "d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592"


@pytest.fixture
def sample(tmp_path):
    """A 300,001-byte file (not a multiple of any chunk size) and its digest."""
    data = os.urandom(300_001)
    p = tmp_path / "sample.bin"
    p.write_bytes(data)
    return p, hashlib.sha256(data).hexdigest()


# --------------------------------------------------------------- known-answer vectors
@pytest.mark.parametrize("msg, expected", [
    (b"", EMPTY), (b"abc", ABC), (MSG_448, MSG_448_HASH), (MSG_896, MSG_896_HASH),
    (FOX.encode(), FOX_HASH)])
def test_known_vectors_bytes(msg, expected):
    assert hash_bytes(msg) == expected


def test_one_million_a():
    assert hash_bytes(b"a" * 1_000_000) == MILLION_A_HASH


def test_empty_string():
    assert hash_text("") == EMPTY


def test_simple_text():
    assert hash_text("abc") == ABC
    assert hash_text(FOX) == FOX_HASH


def test_digest_format_is_256_bits():
    d = hash_text("IE3082")
    assert len(d) == DIGEST_HEX_LEN == 64
    assert d == d.lower() and int(d, 16).bit_length() <= 256
    assert len(bytes.fromhex(d)) == 32


def test_text_depends_on_encoding():
    # SHA-256 hashes bytes: the same characters in different encodings differ
    assert hash_text("é", "utf-8") != hash_text("é", "latin-1")
    assert hash_text("abc", "utf-16") != ABC


def test_binary_input_all_byte_values():
    data = bytes(range(256))
    assert hash_bytes(data) == hashlib.sha256(data).hexdigest()
    assert hash_bytes(bytearray(data)) == hash_bytes(memoryview(data)) == hash_bytes(data)


def test_type_errors():
    with pytest.raises(TypeError):
        hash_bytes("abc")                 # str must go through hash_text
    with pytest.raises(TypeError):
        hash_bytes(123)
    with pytest.raises(TypeError):
        hash_text(b"abc")


# --------------------------------------------------------------- determinism / sensitivity
def test_same_input_same_digest():
    data = os.urandom(4096)
    assert len({hash_bytes(data) for _ in range(20)}) == 1


def test_changed_input_changes_digest():
    data = bytearray(os.urandom(4096))
    before = hash_bytes(bytes(data))
    data[100] ^= 0x01                     # one bit
    assert hash_bytes(bytes(data)) != before
    assert hash_text("abc") != hash_text("abd") != hash_text("abc ")


def test_single_bit_flips_change_about_half_the_bits():
    base = bytes(1024)
    h0 = hash_bytes(base)
    dists = []
    for i in range(0, 8192, 41):          # 200 different bit positions
        m = bytearray(base)
        m[i // 8] ^= 1 << (i % 8)
        dists.append(hamming_distance(h0, hash_bytes(bytes(m))))
    assert all(d > 0 for d in dists)
    mean = sum(dists) / len(dists)
    assert 120 < mean < 136               # ideal 128; SD of the mean here is about 0.6


# --------------------------------------------------------------- file hashing
def test_file_hash_matches_hashlib(sample):
    p, expected = sample
    assert hash_file(p) == expected
    assert hash_file(str(p)) == expected  # str paths work too


def test_known_vector_via_file(tmp_path):
    p = tmp_path / "abc.txt"
    p.write_bytes(b"abc")
    assert hash_file(p) == ABC
    empty = tmp_path / "empty.bin"
    empty.write_bytes(b"")
    assert hash_file(empty) == EMPTY


def test_file_is_read_in_binary_mode(tmp_path):
    # Text mode on Windows would turn \r\n into \n and change the digest
    data = b"line1\r\nline2\r\n"
    p = tmp_path / "crlf.txt"
    p.write_bytes(data)
    assert hash_file(p) == hashlib.sha256(data).hexdigest()


@pytest.mark.parametrize("chunk", [1, 63, 64, 65, 1000, 4096, DEFAULT_CHUNK_SIZE, 1024**2, 10**7])
def test_chunked_equals_one_shot(sample, chunk):
    p, expected = sample
    assert hash_file_chunked(p, chunk) == expected


@pytest.mark.parametrize("size", [0, 1, 55, 56, 63, 64, 65, DEFAULT_CHUNK_SIZE - 1,
                                  DEFAULT_CHUNK_SIZE, DEFAULT_CHUNK_SIZE + 1])
def test_padding_and_chunk_boundaries(tmp_path, size):
    data = os.urandom(size)
    p = tmp_path / f"{size}.bin"
    p.write_bytes(data)
    expected = hashlib.sha256(data).hexdigest()
    assert hash_file(p) == hash_file_whole(p) == hash_file_chunked(p, 64) == expected


def test_large_file(tmp_path):
    # 20 MiB + 7 bytes: many chunks, and the last chunk is partial
    block = os.urandom(1024**2)
    p = tmp_path / "large.bin"
    ref = hashlib.sha256()
    with open(p, "wb") as f:
        for _ in range(20):
            f.write(block)
            ref.update(block)
        f.write(b"tail!!!")
        ref.update(b"tail!!!")
    assert hash_file(p) == hash_file_chunked(p, 1024**2) == ref.hexdigest()


def test_generated_50mb_dataset_matches_manifest():
    from benchmarks.sha256_integrity_demo import manifest_digests, ROOT
    p = ROOT / "datasets" / "data" / "BIN" / "50MB.bin"
    if not p.exists():
        pytest.skip("datasets not generated")
    assert hash_file(p) == manifest_digests()["datasets/data/BIN/50MB.bin"]


def test_invalid_path(tmp_path):
    with pytest.raises(FileNotFoundError):
        hash_file(tmp_path / "does_not_exist.bin")
    with pytest.raises(FileNotFoundError):
        verify_file_hash(tmp_path / "does_not_exist.bin", EMPTY)


def test_directory_path(tmp_path):
    with pytest.raises(IsADirectoryError):
        hash_file(tmp_path)


@pytest.mark.parametrize("bad", [0, -1, 1.5, "64", True, None])
def test_invalid_chunk_size(sample, bad):
    with pytest.raises(ValueError):
        hash_file_chunked(sample[0], bad)


# --------------------------------------------------------------- comparison / integrity
def test_compare_hashes():
    assert compare_hashes(ABC, ABC)
    assert compare_hashes(ABC, "  " + ABC.upper() + "\n")   # case and whitespace ignored
    assert not compare_hashes(ABC, EMPTY)


@pytest.mark.parametrize("bad", ["", "abc", ABC[:-1], ABC + "0", "g" * 64, ABC[:32] + " " + ABC[33:]])
def test_malformed_digest_rejected(bad):
    with pytest.raises(ValueError):
        normalise_digest(bad)
    with pytest.raises(ValueError):
        compare_hashes(ABC, bad)


def test_integrity_unchanged_file_passes(sample):
    p, expected = sample
    assert verify_file_hash(p, expected)
    res = integrity_check(p, expected)
    assert isinstance(res, IntegrityResult)
    assert res.match and res.status == "PASS" and res.differing_bits == 0


@pytest.mark.parametrize("modify", ["bit", "byte", "append", "truncate"])
def test_integrity_modified_file_fails(sample, modify):
    p, expected = sample
    data = bytearray(p.read_bytes())
    if modify == "bit":
        data[150_000] ^= 0x01
    elif modify == "byte":
        data[0] = (data[0] + 1) % 256
    elif modify == "append":
        data += b"\x00"
    else:
        data = data[:-1]
    p.write_bytes(bytes(data))
    assert not verify_file_hash(p, expected)
    res = integrity_check(p, expected)
    assert res.status == "FAIL" and res.actual != res.expected and res.differing_bits > 0


def test_verify_rejects_malformed_reference(sample):
    with pytest.raises(ValueError):
        verify_file_hash(sample[0], "not-a-digest")


def test_hamming_distance():
    assert hamming_distance(ABC, ABC) == 0
    assert hamming_distance("0" * 64, "f" * 64) == 256
    assert hamming_distance("0" * 64, "0" * 63 + "1") == 1
    assert hamming_distance("0" * 64, "8" + "0" * 63) == 1


# --------------------------------------------------------------- HMAC vs plain SHA-256
def test_hmac_rfc4231_vectors():
    assert hmac_sha256(b"\x0b" * 20, b"Hi There") == \
        "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
    assert hmac_sha256(b"Jefe", b"what do ya want for nothing?") == \
        "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"


def test_hmac_is_not_plain_or_prefixed_sha256():
    key, msg = b"Jefe", b"what do ya want for nothing?"
    tag = hmac_sha256(key, msg)
    assert tag != hash_bytes(msg)
    assert tag != hash_bytes(key + msg)
    assert tag != hmac_sha256(b"Jeff", msg)            # different key, different tag
