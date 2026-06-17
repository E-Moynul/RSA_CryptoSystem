"""Tests for rsa_crypto.keygen"""

import pytest

from rsa_crypto.keygen import (
    extended_gcd,
    gcd,
    generate_keypair,
    mod_inverse,
)




@pytest.mark.parametrize(
    "a,b,expected",
    [
        (12, 18, 6),
        (17, 13, 1),
        (100, 75, 25),
        (0, 5, 5),
        (7, 7, 7),
    ],
)
def test_gcd(a, b, expected):
    assert gcd(a, b) == expected


@pytest.mark.parametrize("a,b", [(35, 15), (240, 46), (17, 13), (1, 1)])
def test_extended_gcd_satisfies_bezout_identity(a, b):
    g, x, y = extended_gcd(a, b)
    assert g == gcd(a, b)
    assert a * x + b * y == g




def test_mod_inverse_correctness():
    assert mod_inverse(3, 11) == 4


def test_mod_inverse_round_trip():
    a, m = 17, 3120 
    inv = mod_inverse(a, m)
    assert (a * inv) % m == 1


def test_mod_inverse_raises_when_not_coprime():
    with pytest.raises(ValueError):
        mod_inverse(4, 8) 




@pytest.mark.parametrize("bits", [64, 128, 256])
def test_generate_keypair_produces_valid_n(bits):
    kp = generate_keypair(bits=bits)
    assert kp.public.n == kp.p * kp.q
    assert kp.private.n == kp.public.n


def test_generate_keypair_e_and_d_are_inverses_mod_phi():
    kp = generate_keypair(bits=128)
    phi = (kp.p - 1) * (kp.q - 1)
    assert (kp.public.e * kp.private.d) % phi == 1


def test_generate_keypair_p_and_q_are_distinct():
    kp = generate_keypair(bits=128)
    assert kp.p != kp.q


def test_generate_keypair_default_e_is_65537():
    kp = generate_keypair(bits=128)
    assert kp.public.e == 65537


def test_generate_keypair_encryption_decryption_inverts():
    kp = generate_keypair(bits=128)
    message = 42
    ciphertext = pow(message, kp.public.e, kp.public.n)
    recovered = pow(ciphertext, kp.private.d, kp.private.n)
    assert recovered == message
