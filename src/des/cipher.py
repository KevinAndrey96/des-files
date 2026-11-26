"""DES (FIPS 46-3) and Triple DES (NIST SP 800-67) on 64-bit blocks.

Educational implementation: correct against the standard test vectors but
neither constant time nor secure. DES has a 56-bit key and was publicly
broken by exhaustive search in 1998.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass

from des.tables import (
    EXPANSION,
    FINAL_PERMUTATION,
    INITIAL_PERMUTATION,
    LEFT_SHIFTS,
    PERMUTATION,
    PERMUTED_CHOICE_1,
    PERMUTED_CHOICE_2,
    S_BOXES,
    WEAK_KEYS,
)

BLOCK_SIZE = 8
_MASK_28 = (1 << 28) - 1
_MASK_32 = (1 << 32) - 1


class KeySizeError(ValueError):
    """Raised when a key or block has the wrong length."""


def permute(value: int, table: Sequence[int], width: int) -> int:
    """Output bit i is input bit table[i], counting from the most significant."""
    result = 0
    for position in table:
        result = (result << 1) | ((value >> (width - position)) & 1)

    return result


def _rotate_left_28(value: int, count: int) -> int:
    return ((value << count) | (value >> (28 - count))) & _MASK_28


def key_schedule(key: bytes) -> list[int]:
    """The sixteen 48-bit round keys; parity bits of the key are ignored."""
    if len(key) != BLOCK_SIZE:
        raise KeySizeError("a DES key has 8 bytes")
    selected = permute(int.from_bytes(key), PERMUTED_CHOICE_1, 64)
    c, d = selected >> 28, selected & _MASK_28
    subkeys = []
    for shift in LEFT_SHIFTS:
        c, d = _rotate_left_28(c, shift), _rotate_left_28(d, shift)
        subkeys.append(permute((c << 28) | d, PERMUTED_CHOICE_2, 56))

    return subkeys


def feistel(right: int, subkey: int) -> int:
    """f(R, K) = P(S(E(R) xor K))."""
    mixed = permute(right, EXPANSION, 32) ^ subkey
    substituted = 0
    for index, box in enumerate(S_BOXES):
        chunk = (mixed >> (42 - 6 * index)) & 0x3F
        row = ((chunk >> 4) & 0b10) | (chunk & 1)
        column = (chunk >> 1) & 0xF
        substituted = (substituted << 4) | box[row * 16 + column]

    return permute(substituted, PERMUTATION, 32)


@dataclass(frozen=True, slots=True)
class Round:
    number: int
    subkey: int
    left: int
    right: int


def _rounds(block: int, subkeys: Sequence[int]) -> tuple[int, list[Round]]:
    permuted = permute(block, INITIAL_PERMUTATION, 64)
    left, right = permuted >> 32, permuted & _MASK_32
    trace = []
    for number, subkey in enumerate(subkeys, start=1):
        left, right = right, left ^ feistel(right, subkey)
        trace.append(Round(number, subkey, left, right))
    output = permute((right << 32) | left, FINAL_PERMUTATION, 64)

    return output, trace


def _check_block(block: bytes) -> int:
    if len(block) != BLOCK_SIZE:
        raise KeySizeError("a DES block has 8 bytes")

    return int.from_bytes(block)


class DES:
    """Single DES; decryption runs the same network with reversed keys."""

    block_size = BLOCK_SIZE

    def __init__(self, key: bytes) -> None:
        self._subkeys = key_schedule(key)
        self.weak = bytes(key) in WEAK_KEYS

    def encrypt_block(self, block: bytes) -> bytes:
        return _rounds(_check_block(block), self._subkeys)[0].to_bytes(BLOCK_SIZE)

    def decrypt_block(self, block: bytes) -> bytes:
        return _rounds(_check_block(block), self._subkeys[::-1])[0].to_bytes(BLOCK_SIZE)

    def trace(self, block: bytes) -> list[Round]:
        """Left and right halves after each of the 16 encryption rounds."""
        return _rounds(_check_block(block), self._subkeys)[1]


class TripleDES:
    """EDE: C = E_K3(D_K2(E_K1(P))) with a 16-byte (K3 = K1) or 24-byte key."""

    block_size = BLOCK_SIZE

    def __init__(self, key: bytes) -> None:
        if len(key) == 2 * BLOCK_SIZE:
            key += key[:BLOCK_SIZE]
        if len(key) != 3 * BLOCK_SIZE:
            raise KeySizeError("a Triple DES key has 16 or 24 bytes")
        self._first, self._second, self._third = (
            DES(key[start : start + BLOCK_SIZE]) for start in range(0, 24, BLOCK_SIZE)
        )

    def encrypt_block(self, block: bytes) -> bytes:
        return self._third.encrypt_block(
            self._second.decrypt_block(self._first.encrypt_block(block))
        )

    def decrypt_block(self, block: bytes) -> bytes:
        return self._first.decrypt_block(
            self._second.encrypt_block(self._third.decrypt_block(block))
        )
