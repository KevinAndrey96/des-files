import pytest
from cryptography.hazmat.decrepit.ciphers.algorithms import TripleDES as ReferenceTripleDES
from cryptography.hazmat.primitives.ciphers import Cipher, modes
from hypothesis import given
from hypothesis import strategies as st

from des import DES, KeySizeError, TripleDES, key_schedule

blocks = st.binary(min_size=8, max_size=8)


def reference_encrypt(key: bytes, block: bytes) -> bytes:
    """OpenSSL through cryptography; Triple DES with K1 = K2 = K3 is single DES."""
    if len(key) == 8:
        key *= 3
    encryptor = Cipher(ReferenceTripleDES(key), modes.ECB()).encryptor()

    return encryptor.update(block) + encryptor.finalize()


@pytest.mark.parametrize(
    ("key", "plaintext", "ciphertext"),
    [
        ("133457799BBCDFF1", "0123456789ABCDEF", "85E813540F0AB405"),
        ("0E329232EA6D0D73", "8787878787878787", "0000000000000000"),
        ("0123456789ABCDEF", "4E6F772069732074", "3FA40E8A984D4815"),
        ("0101010101010101", "95F8A5E5DD31D900", "8000000000000000"),
        ("8001010101010101", "0000000000000000", "95A8D72813DAA94D"),
    ],
)
def test_published_vectors(key: str, plaintext: str, ciphertext: str) -> None:
    cipher = DES(bytes.fromhex(key))

    assert cipher.encrypt_block(bytes.fromhex(plaintext)).hex().upper() == ciphertext
    assert cipher.decrypt_block(bytes.fromhex(ciphertext)).hex().upper() == plaintext


def test_sp800_67_triple_des_vector() -> None:
    cipher = TripleDES(bytes.fromhex("0123456789ABCDEF23456789ABCDEF01456789ABCDEF0123"))
    plaintext = b"The qufck brown fox jump"
    ciphertext = b"".join(cipher.encrypt_block(plaintext[i : i + 8]) for i in range(0, 24, 8))

    assert ciphertext.hex().upper() == "A826FD8CE53B855FCCE21C8112256FE668D5C05DD9B6B900"


def test_key_schedule_matches_the_worked_example() -> None:
    subkeys = key_schedule(bytes.fromhex("133457799BBCDFF1"))

    assert f"{subkeys[0]:012X}" == "1B02EFFC7072"
    assert f"{subkeys[15]:012X}" == "CB3D8B0E17F5"


def test_trace_exposes_sixteen_rounds() -> None:
    trace = DES(bytes.fromhex("133457799BBCDFF1")).trace(bytes.fromhex("0123456789ABCDEF"))

    assert [state.number for state in trace] == list(range(1, 17))
    assert (trace[0].left, trace[0].right) == (0xF0AAF0AA, 0xEF4A6544)
    assert (trace[-1].left, trace[-1].right) == (0x43423234, 0x0A4CD995)


@given(st.binary(min_size=8, max_size=8), blocks)
def test_matches_openssl_for_single_des(key: bytes, block: bytes) -> None:
    assert DES(key).encrypt_block(block) == reference_encrypt(key, block)


@given(st.binary(min_size=24, max_size=24), blocks)
def test_matches_openssl_for_triple_des(key: bytes, block: bytes) -> None:
    cipher = TripleDES(key)

    assert cipher.encrypt_block(block) == reference_encrypt(key, block)
    assert cipher.decrypt_block(cipher.encrypt_block(block)) == block


@given(st.binary(min_size=8, max_size=8), blocks)
def test_complementation_property(key: bytes, block: bytes) -> None:
    def complement(data: bytes) -> bytes:
        return bytes(byte ^ 0xFF for byte in data)

    assert DES(complement(key)).encrypt_block(complement(block)) == complement(
        DES(key).encrypt_block(block)
    )


@given(st.sampled_from(["0101010101010101", "FEFEFEFEFEFEFEFE", "E0E0E0E0F1F1F1F1"]), blocks)
def test_weak_keys_are_involutions(key: str, block: bytes) -> None:
    cipher = DES(bytes.fromhex(key))

    assert cipher.weak
    assert cipher.encrypt_block(cipher.encrypt_block(block)) == block


def test_two_key_triple_des_reuses_the_first_key() -> None:
    k1, k2 = bytes.fromhex("0123456789ABCDEF"), bytes.fromhex("FEDCBA9876543210")
    block = b"8 bytes!"

    assert TripleDES(k1 + k2).encrypt_block(block) == TripleDES(k1 + k2 + k1).encrypt_block(block)
    assert TripleDES(k1 * 3).encrypt_block(block) == DES(k1).encrypt_block(block)


@pytest.mark.parametrize(
    ("factory", "key", "message"),
    [(DES, b"short", "8 bytes"), (TripleDES, b"x" * 20, "16 or 24 bytes")],
)
def test_rejects_wrong_key_sizes(factory: type[DES | TripleDES], key: bytes, message: str) -> None:
    with pytest.raises(KeySizeError, match=message):
        factory(key)


def test_rejects_wrong_block_sizes() -> None:
    with pytest.raises(KeySizeError, match="block has 8 bytes"):
        DES(bytes(8)).encrypt_block(b"seven!!")
