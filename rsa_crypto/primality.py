"""
primality.py
-------------
Probabilistic primality testing and large prime generation.
"""

import random


def is_prime_miller_rabin(n: int, rounds: int = 40) -> bool:
    """Miller-Rabin probabilistic primality test."""
    if n < 2:
        return False
    if n in (2, 3):
        return True
    if n % 2 == 0:
        return False

    r, d = 0, n - 1
    while d % 2 == 0:
        d //= 2
        r += 1

    for _ in range(rounds):
        a = random.randrange(2, n - 1)
        x = pow(a, d, n)

        if x == 1 or x == n - 1:
            continue 

        composite = True
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                composite = False
                break

        if composite:
            return False

    return True


def generate_prime_candidate(bits: int) -> int:
    """Generate a random odd integer with the top and bottom bits set."""
    candidate = random.getrandbits(bits)
    candidate |= (1 << bits - 1) | 1
    return candidate


def generate_large_prime(bits: int = 512) -> int:
    while True:
        candidate = generate_prime_candidate(bits)
        if is_prime_miller_rabin(candidate):
            return candidate


if __name__ == "__main__":
    # quick manual sanity check
    print("Testing known primes/composites:")
    for n in [2, 17, 18, 97, 100, 7919, 7920]:
        print(f"  {n}: {'prime' if is_prime_miller_rabin(n) else 'composite'}")

    print("\nGenerating a 256-bit prime...")
    p = generate_large_prime(256)
    print(f"  {p}\n  (bit length: {p.bit_length()})")
