"""ECB and CBC modes with PKCS #7 padding for any 64-bit block cipher."""

from __future__ import annotations

from typing import Protocol

BLOCK_SIZE = 8


class BlockCipher(Protocol):
    def encrypt_block(self, block: bytes) -> bytes: ...

    def decrypt_block(self, block: bytes) -> bytes: ...


class PaddingError(ValueError):
    """Raised when decrypted data does not end in valid PKCS #7 padding."""


def pad(data: bytes) -> bytes:
    count = BLOCK_SIZE - len(data) % BLOCK_SIZE

    return data + bytes([count]) * count


def unpad(data: bytes) -> bytes:
    if not data or len(data) % BLOCK_SIZE:
        raise PaddingError("padded data must be a non empty multiple of 8 bytes")
    count = data[-1]
    if not 1 <= count <= BLOCK_SIZE or data[-count:] != bytes([count]) * count:
        raise PaddingError("invalid PKCS #7 padding")

    return data[:-count]


def _blocks(data: bytes) -> list[bytes]:
    if len(data) % BLOCK_SIZE:
        raise PaddingError("ciphertext must be a multiple of 8 bytes")

    return [data[start : start + BLOCK_SIZE] for start in range(0, len(data), BLOCK_SIZE)]


def _xor(left: bytes, right: bytes) -> bytes:
    return bytes(a ^ b for a, b in zip(left, right, strict=True))


def encrypt_ecb(cipher: BlockCipher, data: bytes) -> bytes:
    """Equal plaintext blocks give equal ciphertext blocks: avoid in practice."""
    return b"".join(cipher.encrypt_block(block) for block in _blocks(pad(data)))


def decrypt_ecb(cipher: BlockCipher, data: bytes) -> bytes:
    return unpad(b"".join(cipher.decrypt_block(block) for block in _blocks(data)))


def _check_iv(iv: bytes) -> None:
    if len(iv) != BLOCK_SIZE:
        raise ValueError("the CBC initialization vector has 8 bytes")


def encrypt_cbc(cipher: BlockCipher, iv: bytes, data: bytes) -> bytes:
    """C_i = E(P_i xor C_(i-1)), C_0 = IV; the IV must be unpredictable."""
    _check_iv(iv)
    previous, output = iv, []
    for block in _blocks(pad(data)):
        previous = cipher.encrypt_block(_xor(block, previous))
        output.append(previous)

    return b"".join(output)


def decrypt_cbc(cipher: BlockCipher, iv: bytes, data: bytes) -> bytes:
    _check_iv(iv)
    previous, output = iv, []
    for block in _blocks(data):
        output.append(_xor(cipher.decrypt_block(block), previous))
        previous = block

    return unpad(b"".join(output))
