"""
keygen.py
---------
RSA key pair generation.
"""

from dataclasses import dataclass

from rsa_crypto.primality import generate_large_prime


@dataclass(frozen=True)
class PublicKey:
    n: int
    e: int


@dataclass(frozen=True)
class PrivateKey:
    n: int
    d: int


@dataclass(frozen=True)
class KeyPair:
    public: PublicKey
    private: PrivateKey
    p: int  
    q: int  


def gcd(a: int, b: int) -> int:
    """Euclidean algorithm for greatest common divisor."""
    while b != 0:
        a, b = b, a % b
    return a


def extended_gcd(a: int, b: int) -> tuple[int, int, int]:
    """
    Extended Euclidean Algorithm.
    """
    old_r, r = a, b
    old_s, s = 1, 0
    old_t, t = 0, 1

    while r != 0:
        quotient = old_r // r
        old_r, r = r, old_r - quotient * r
        old_s, s = s, old_s - quotient * s
        old_t, t = t, old_t - quotient * t

    return old_r, old_s, old_t 


def mod_inverse(a: int, m: int) -> int:
    """
    Modular multiplicative inverse of a mod m, using the Extended
    Euclidean Algorithm.
    """
    g, x, _ = extended_gcd(a, m)
    if g != 1:
        raise ValueError(f"{a} has no modular inverse mod {m} (gcd = {g})")
    return x % m


def generate_keypair(bits: int = 1024, e: int = 65537) -> KeyPair:
    """
    Generate a full RSA key pair.
    """
    p = generate_large_prime(bits)
    q = generate_large_prime(bits)


    while p == q:
        q = generate_large_prime(bits)

    n = p * q
    phi = (p - 1) * (q - 1)


    if gcd(e, phi) != 1:
        candidate = 3
        while gcd(candidate, phi) != 1:
            candidate += 2
        e = candidate

    d = mod_inverse(e, phi)

    return KeyPair(
        public=PublicKey(n=n, e=e),
        private=PrivateKey(n=n, d=d),
        p=p,
        q=q,
    )


if __name__ == "__main__":
    print("Generating a 512-bit-per-prime RSA key pair (1024-bit n)...\n")
    kp = generate_keypair(bits=512)

    print(f"p = {kp.p}")
    print(f"q = {kp.q}")
    print(f"\nPublic key  (n, e): ({kp.public.n}, {kp.public.e})")
    print(f"Private key (n, d): ({kp.private.n}, {kp.private.d})")
    print(f"\nn bit length: {kp.public.n.bit_length()}")
