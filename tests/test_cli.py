import io
import subprocess
import sys

import pytest

from des.cli import main

KEY = "133457799BBCDFF1"


def run(argv: list[str]) -> tuple[int, str]:
    output = io.StringIO()

    return main(argv, stdout=output), output.getvalue()


def test_block_both_ways() -> None:
    assert run(["block", "-k", KEY, "0123456789ABCDEF"]) == (0, "85E813540F0AB405\n")
    assert run(["block", "-k", KEY, "--decrypt", "85E813540F0AB405"]) == (0, "0123456789ABCDEF\n")


def test_trace_prints_every_round() -> None:
    status, output = run(["trace", "-k", KEY, "0123456789ABCDEF"])
    lines = output.splitlines()

    assert status == 0
    assert lines[0] == "ronda  1  K=1B02EFFC7072  L=F0AAF0AA  R=EF4A6544"
    assert lines[-1] == "salida    85E813540F0AB405"
    assert len(lines) == 17


def test_cbc_with_random_iv_round_trips() -> None:
    status, ciphertext = run(["encrypt", "-k", KEY, "mensaje secreto"])

    assert status == 0
    assert len(ciphertext.strip()) == 2 * (8 + 16)
    assert run(["decrypt", "-k", KEY, ciphertext.strip()]) == (0, "mensaje secreto\n")


def test_cbc_with_explicit_iv_and_ecb() -> None:
    iv = ["--iv", "0001010001010000"]
    status, ciphertext = run(["encrypt", "-k", KEY, *iv, "hola"])

    assert status == 0
    assert run(["decrypt", "-k", KEY, *iv, ciphertext.strip()]) == (0, "hola\n")
    status, ciphertext = run(["encrypt", "-k", KEY * 2, "--mode", "ecb", "hola"])
    assert run(["decrypt", "-k", KEY * 2, "--mode", "ecb", ciphertext.strip()]) == (0, "hola\n")


def test_warns_about_weak_keys(capsys: pytest.CaptureFixture[str]) -> None:
    assert run(["block", "-k", "0101010101010101", "0000000000000000"])[0] == 0
    assert "clave débil" in capsys.readouterr().err


@pytest.mark.parametrize(
    "argv",
    [
        ["block", "-k", "XYZ", "00"],
        ["block", "-k", KEY, "0011"],
        ["trace", "-k", KEY * 2, "0123456789ABCDEF"],
        ["decrypt", "-k", KEY, "--mode", "ecb", "0123456789ABCDEF"],
        ["encrypt", "-k", KEY, "--iv", "00", "hola"],
    ],
)
def test_reports_errors_with_exit_code_two(
    argv: list[str], capsys: pytest.CaptureFixture[str]
) -> None:
    assert run(argv) == (2, "")
    assert capsys.readouterr().err.startswith("error:")


def test_module_entry_point() -> None:
    completed = subprocess.run(
        [sys.executable, "-m", "des", "block", "-k", "0123456789ABCDEF", "4E6F772069732074"],
        capture_output=True,
        text=True,
        check=True,
    )

    assert completed.stdout == "3FA40E8A984D4815\n"
