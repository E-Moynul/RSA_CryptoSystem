"""
weak_key_attack.py
-------------------
Demonstrates *why* RSA key parameters matter, by actually breaking a
deliberately weak key.
"""

import math
import time

from rsa_crypto.keygen import generate_keypair, mod_inverse
from rsa_crypto.primality import generate_large_prime


def fermat_factorize(n: int, max_iterations: int = 10_000_000):
    """
    Attempt to factor n using Fermat's method.
    """
  
    a = math.isqrt(n) + 1
    iterations = 0

    while iterations < max_iterations:
        b_squared = a * a - n
        b = math.isqrt(b_squared)

        if b * b == b_squared:
            p, q = a - b, a + b
            return p, q, iterations

        a += 1
        iterations += 1

    return None, None, iterations


def make_weak_keypair(bits: int = 256):
    p = generate_large_prime(bits)
    candidate = p + 2
    while True:
        from rsa_crypto.primality import is_prime_miller_rabin
        if is_prime_miller_rabin(candidate):
            q = candidate
            break
        candidate += 2

    n = p * q
    phi = (p - 1) * (q - 1)
    e = 65537
    d = mod_inverse(e, phi)
    return p, q, n, e, d


def demo_weak_key_attack():
    print("=" * 70)
    print("DEMONSTRATION: Fermat Factorization Attack on a Weak RSA Key")
    print("=" * 70)

    print("\n[1] Generating a WEAK key (p and q chosen close together)...")
    p, q, n, e, d = make_weak_keypair(bits=256)
    print(f"    p = {p}")
    print(f"    q = {q}")
    print(f"    n = p * q  ({n.bit_length()}-bit modulus)")
    print(f"    |p - q| = {abs(p - q)}   <-- dangerously small gap")

    print("\n[2] Attacker only knows the public key (n, e). Attempting to")
    print("    factor n using Fermat's method...")

    start = time.perf_counter()
    found_p, found_q, iterations = fermat_factorize(n)
    elapsed = time.perf_counter() - start

    if found_p is not None:
        print(f"\n    >>> FACTORED in {iterations} iteration(s), {elapsed:.4f}s <<<")
        print(f"    Recovered p = {found_p}")
        print(f"    Recovered q = {found_q}")
        print(f"    Match: {sorted([found_p, found_q]) == sorted([p, q])}")

        recovered_phi = (found_p - 1) * (found_q - 1)
        recovered_d = mod_inverse(e, recovered_phi)
        print(f"    Recovered private exponent d matches original: {recovered_d == d}")
        print("\n    The attacker can now decrypt ANY message encrypted with")
        print("    this public key, despite never having seen the private key.")
    else:
        print(f"\n    Factorization did not complete within {iterations} iterations.")

    print("\n" + "-" * 70)
    print("[3] Control case: factoring a PROPERLY generated key (p, q random")
    print("    and independent, not artificially close together).")

    safe_kp = generate_keypair(bits=256)
    print(f"    |p - q| = {abs(safe_kp.p - safe_kp.q)}  (astronomically larger gap)")

    start = time.perf_counter()
    safe_p, safe_q, safe_iterations = fermat_factorize(
        safe_kp.public.n, max_iterations=2_000_000
    )
    elapsed = time.perf_counter() - start

    if safe_p is not None:
        print(f"    Unexpectedly factored in {safe_iterations} iterations (very unlucky).")
    else:
        print(f"    Fermat's method FAILED after {safe_iterations:,} iterations "
              f"({elapsed:.2f}s) - as expected.")
        print("    This is why proper random, independent prime generation matters.")

    print("\n" + "=" * 70)
    print("TAKEAWAY: RSA's security depends not just on key SIZE, but on the")
    print("primes being generated independently and randomly. A large n is")
    print("not protective if p and q are correlated or too close together.")
    print("=" * 70)


if __name__ == "__main__":
    demo_weak_key_attack()
