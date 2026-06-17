"""Tests for rsa_crypto.primality"""

import pytest

from rsa_crypto.primality import (
    generate_large_prime,
    generate_prime_candidate,
    is_prime_miller_rabin,
)


KNOWN_PRIMES = [2, 3, 5, 7, 11, 13, 97, 7919, 104729]
KNOWN_COMPOSITES = [0, 1, 4, 6, 9, 100, 7920, 1000000]


CARMICHAEL_NUMBERS = [561, 1105, 1729, 2465, 2821]


@pytest.mark.parametrize("n", KNOWN_PRIMES)
def test_known_primes_are_identified_as_prime(n):
    assert is_prime_miller_rabin(n) is True


@pytest.mark.parametrize("n", KNOWN_COMPOSITES)
def test_known_composites_are_identified_as_composite(n):
    assert is_prime_miller_rabin(n) is False


@pytest.mark.parametrize("n", CARMICHAEL_NUMBERS)
def test_carmichael_numbers_are_not_fooled(n):
    assert is_prime_miller_rabin(n) is False


def test_negative_numbers_are_not_prime():
    assert is_prime_miller_rabin(-7) is False


def test_generate_prime_candidate_has_correct_bit_length():
    candidate = generate_prime_candidate(128)
    assert candidate.bit_length() == 128


def test_generate_prime_candidate_is_odd():
    for _ in range(20):
        candidate = generate_prime_candidate(64)
        assert candidate % 2 == 1


@pytest.mark.parametrize("bits", [64, 128, 256])
def test_generate_large_prime_is_actually_prime(bits):
    p = generate_large_prime(bits)
    assert is_prime_miller_rabin(p, rounds=64)


@pytest.mark.parametrize("bits", [64, 128, 256])
def test_generate_large_prime_has_correct_bit_length(bits):
    p = generate_large_prime(bits)
    assert p.bit_length() == bits
