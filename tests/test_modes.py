import pytest
from cryptography.hazmat.decrepit.ciphers.algorithms import TripleDES as ReferenceTripleDES
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, modes
from hypothesis import given
from hypothesis import strategies as st

from des import (
    DES,
    PaddingError,
    TripleDES,
    decrypt_cbc,
    decrypt_ecb,
    encrypt_cbc,
    encrypt_ecb,
    pad,
    unpad,
)

KEY = bytes.fromhex("0123456789ABCDEF23456789ABCDEF01456789ABCDEF0123")
IV = bytes.fromhex("F69F2445DF4F9B17")


def reference_cbc(data: bytes) -> bytes:
    padder = padding.PKCS7(64).padder()
    padded = padder.update(data) + padder.finalize()
    encryptor = Cipher(ReferenceTripleDES(KEY), modes.CBC(IV)).encryptor()

    return encryptor.update(padded) + encryptor.finalize()


@pytest.mark.parametrize(
    ("data", "padded"),
    [(b"", b"\x08" * 8), (b"abc", b"abc" + b"\x05" * 5), (b"12345678", b"12345678" + b"\x08" * 8)],
)
def test_pkcs7(data: bytes, padded: bytes) -> None:
    assert pad(data) == padded
    assert unpad(padded) == data


@pytest.mark.parametrize(
    ("data", "message"),
    [
        (b"", "non empty multiple"),
        (b"abc", "non empty multiple"),
        (b"1234567\x00", "invalid"),
        (b"1234567\x09", "invalid"),
        (b"123456\x01\x02", "invalid"),
    ],
)
def test_rejects_bad_padding(data: bytes, message: str) -> None:
    with pytest.raises(PaddingError, match=message):
        unpad(data)


@given(st.binary(max_size=100))
def test_cbc_matches_openssl(data: bytes) -> None:
    ciphertext = encrypt_cbc(TripleDES(KEY), IV, data)

    assert ciphertext == reference_cbc(data)
    assert decrypt_cbc(TripleDES(KEY), IV, ciphertext) == data


@given(st.binary(max_size=100))
def test_ecb_round_trip(data: bytes) -> None:
    cipher = DES(KEY[:8])

    assert decrypt_ecb(cipher, encrypt_ecb(cipher, data)) == data


def test_ecb_leaks_repeated_blocks_and_cbc_does_not() -> None:
    cipher = DES(KEY[:8])
    data = b"SAMEBLOK" * 3
    ecb, cbc = encrypt_ecb(cipher, data), encrypt_cbc(cipher, IV, data)

    assert ecb[:8] == ecb[8:16] == ecb[16:24]
    assert len({cbc[:8], cbc[8:16], cbc[16:24]}) == 3


def test_rejects_partial_ciphertext_and_bad_iv() -> None:
    cipher = DES(KEY[:8])

    with pytest.raises(PaddingError, match="multiple of 8"):
        decrypt_cbc(cipher, IV, b"123")
    with pytest.raises(ValueError, match="initialization vector"):
        encrypt_cbc(cipher, b"short", b"data")
