"""Tests for rsa_crypto.cipher"""

import pytest

from rsa_crypto.cipher import (
    decrypt_int,
    decrypt_message,
    encrypt_int,
    encrypt_message,
)
from rsa_crypto.keygen import generate_keypair


@pytest.fixture(scope="module")
def keypair():
    return generate_keypair(bits=256)



def test_encrypt_decrypt_int_round_trip(keypair):
    message = 12345
    ciphertext = encrypt_int(message, keypair.public)
    recovered = decrypt_int(ciphertext, keypair.private)
    assert recovered == message


def test_encrypt_int_rejects_message_too_large(keypair):
    too_large = keypair.public.n + 1
    with pytest.raises(ValueError):
        encrypt_int(too_large, keypair.public)


def test_encrypt_is_deterministic_for_same_message(keypair):
    """Documents the known textbook-RSA property: identical plaintext
    integers always produce identical ciphertexts (no randomized padding).
    This is intentional here and explained in cipher.py's docstring."""
    c1 = encrypt_int(99, keypair.public)
    c2 = encrypt_int(99, keypair.public)
    assert c1 == c2



@pytest.mark.parametrize(
    "message",
    [
        "Hello, RSA!",
        "A",
        "",
        "The quick brown fox jumps over the lazy dog. " * 5,
        "বাংলা",
        "emoji test 🔐🔑✨",
        "Mixed: English, বাংলা, 数字123, émojis 🚀",
    ],
)
def test_encrypt_decrypt_message_round_trip(keypair, message):
    encrypted = encrypt_message(message, keypair.public)
    decrypted = decrypt_message(encrypted, keypair.private)
    assert decrypted == message


def test_long_message_splits_into_multiple_blocks(keypair):
    long_message = "x" * 500
    encrypted = encrypt_message(long_message, keypair.public)
    assert len(encrypted) > 1

    decrypted = decrypt_message(encrypted, keypair.private)
    assert decrypted == long_message


def test_different_keypairs_produce_different_ciphertexts():
    kp1 = generate_keypair(bits=256)
    kp2 = generate_keypair(bits=256)
    message = "Same message, different keys"

    enc1 = encrypt_message(message, kp1.public)
    enc2 = encrypt_message(message, kp2.public)

    assert enc1 != enc2
    assert decrypt_message(enc1, kp1.private) == message
    assert decrypt_message(enc2, kp2.private) == message


def test_wrong_private_key_does_not_decrypt_correctly():
    kp1 = generate_keypair(bits=256)
    kp2 = generate_keypair(bits=256)
    message = "Secret message"

    encrypted = encrypt_message(message, kp1.public)

    try:
        wrong_decryption = decrypt_message(encrypted, kp2.private)
        assert wrong_decryption != message
    except (UnicodeDecodeError, ValueError):
        pass
