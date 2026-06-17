"""
cipher.py
---------
RSA encryption and decryption.
"""

from rsa_crypto.keygen import PrivateKey, PublicKey


def encrypt_int(message: int, public_key: PublicKey) -> int:
    """Encrypt using the public key: c = m^e mod n."""
    if message >= public_key.n:
        raise ValueError(
            "Message integer must be smaller than the modulus n. "
            "Use encrypt_message() for text longer than the key allows."
        )
    return pow(message, public_key.e, public_key.n)


def decrypt_int(ciphertext: int, private_key: PrivateKey) -> int:
    """Decrypt using the private key: m = c^d mod n."""
    return pow(ciphertext, private_key.d, private_key.n)


def encrypt_message(message: str, public_key: PublicKey) -> list[int]:
    max_chunk_bytes = max(1, (public_key.n.bit_length() // 8) - 1)

    data = message.encode("utf-8")
    chunks = [
        data[i:i + max_chunk_bytes]
        for i in range(0, len(data), max_chunk_bytes)
    ]

    ciphertext_blocks = []
    for chunk in chunks:
        block_int = int.from_bytes(chunk, byteorder="big")
        ciphertext_blocks.append(encrypt_int(block_int, public_key))

    return ciphertext_blocks


def decrypt_message(ciphertext_blocks: list[int], private_key: PrivateKey) -> str:
    """Decrypt a list of ciphertext blocks."""
    decoded_bytes = bytearray()
    for block in ciphertext_blocks:
        block_int = decrypt_int(block, private_key)
        byte_length = max(1, (block_int.bit_length() + 7) // 8)
        decoded_bytes.extend(block_int.to_bytes(byte_length, byteorder="big"))

    return decoded_bytes.decode("utf-8")


if __name__ == "__main__":
    from rsa_crypto.keygen import generate_keypair

    print("Generating keys...")
    kp = generate_keypair(bits=512)

    message = "Hello, RSA! Its a test message 🔐"
    print(f"\nOriginal message: {message}")

    encrypted = encrypt_message(message, kp.public)
    print(f"\nEncrypted blocks ({len(encrypted)} block(s)):")
    for block in encrypted:
        print(f"  {block}")

    decrypted = decrypt_message(encrypted, kp.private)
    print(f"\nDecrypted message: {decrypted}")
    print(f"\nRound-trip successful: {message == decrypted}")
