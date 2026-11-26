"""Command line interface: block operations, round trace and ECB/CBC messages."""

from __future__ import annotations

import argparse
import os
import sys
from collections.abc import Sequence
from typing import TextIO

from des.cipher import BLOCK_SIZE, DES, KeySizeError, TripleDES
from des.modes import decrypt_cbc, decrypt_ecb, encrypt_cbc, encrypt_ecb


class InputError(ValueError):
    """Raised when hexadecimal input cannot be parsed."""


def _hex(value: str, name: str) -> bytes:
    try:
        return bytes.fromhex(value)
    except ValueError as error:
        raise InputError(f"{name} must be hexadecimal") from error


def _cipher(key_hex: str) -> DES | TripleDES:
    key = _hex(key_hex, "key")
    if len(key) == BLOCK_SIZE:
        cipher = DES(key)
        if cipher.weak:
            print("aviso: clave débil, cifrar dos veces devuelve el original", file=sys.stderr)

        return cipher

    return TripleDES(key)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="des", description="DES y Triple DES desde cero (FIPS 46-3), con fines educativos."
    )
    commands = parser.add_subparsers(dest="command", required=True)
    block = commands.add_parser("block", help="cifrar o descifrar un bloque de 8 bytes en hex")
    block.add_argument("--decrypt", action="store_true")
    trace = commands.add_parser("trace", help="mostrar las 16 rondas de un bloque")
    for command in (block, trace):
        command.add_argument("--key", "-k", required=True, help="clave en hex: 8, 16 o 24 bytes")
        command.add_argument("block", help="bloque de 8 bytes en hex")
    for name in ("encrypt", "decrypt"):
        message = commands.add_parser(name, help=f"{name} de un mensaje con relleno PKCS #7")
        message.add_argument("--key", "-k", required=True, help="clave en hex: 8, 16 o 24 bytes")
        message.add_argument("--mode", choices=["cbc", "ecb"], default="cbc")
        message.add_argument("--iv", help="vector de inicialización en hex (CBC)")
        message.add_argument("text", help="texto plano, o criptograma en hex al descifrar")

    return parser


def _run(arguments: argparse.Namespace, target: TextIO) -> None:
    cipher = _cipher(arguments.key)
    if arguments.command == "block":
        data = _hex(arguments.block, "block")
        result = cipher.decrypt_block(data) if arguments.decrypt else cipher.encrypt_block(data)
        target.write(f"{result.hex().upper()}\n")
    elif arguments.command == "trace":
        if not isinstance(cipher, DES):
            raise KeySizeError("the round trace needs a single DES key of 8 bytes")
        for state in cipher.trace(_hex(arguments.block, "block")):
            target.write(
                f"ronda {state.number:2d}  K={state.subkey:012X}  "
                f"L={state.left:08X}  R={state.right:08X}\n"
            )
        target.write(
            f"salida    {cipher.encrypt_block(_hex(arguments.block, 'block')).hex().upper()}\n"
        )
    elif arguments.command == "encrypt":
        plaintext = arguments.text.encode()
        if arguments.mode == "ecb":
            target.write(f"{encrypt_ecb(cipher, plaintext).hex().upper()}\n")
        else:
            if arguments.iv:
                sealed = encrypt_cbc(cipher, _hex(arguments.iv, "iv"), plaintext)
            else:
                iv = os.urandom(BLOCK_SIZE)
                sealed = iv + encrypt_cbc(cipher, iv, plaintext)
            target.write(f"{sealed.hex().upper()}\n")
    else:
        data = _hex(arguments.text, "ciphertext")
        if arguments.mode == "ecb":
            plaintext = decrypt_ecb(cipher, data)
        else:
            iv, data = (_hex(arguments.iv, "iv"), data) if arguments.iv else (data[:8], data[8:])
            plaintext = decrypt_cbc(cipher, iv, data)
        target.write(plaintext.decode(errors="backslashreplace") + "\n")


def main(argv: Sequence[str] | None = None, stdout: TextIO | None = None) -> int:
    arguments = _parser().parse_args(argv)
    try:
        _run(arguments, stdout or sys.stdout)
    except ValueError as error:
        print(f"error: {error}", file=sys.stderr)

        return 2

    return 0
