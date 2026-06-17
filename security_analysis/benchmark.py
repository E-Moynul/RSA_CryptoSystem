"""
benchmark.py
------------
Measures how RSA key generation, encryption, and decryption time scale
with key size, and renders the results as a chart.
"""

import time

import matplotlib.pyplot as plt

from rsa_crypto.cipher import decrypt_int, encrypt_int
from rsa_crypto.keygen import generate_keypair


def benchmark_keysize(bit_sizes, trials_per_size: int = 3):
    results = {
        "bits": [],
        "keygen_time": [],
        "encrypt_time": [],
        "decrypt_time": [],
    }

    for bits in bit_sizes:
        print(f"Benchmarking {bits}-bit primes ({trials_per_size} trial(s))...")

        keygen_times = []
        keypair = None
        for _ in range(trials_per_size):
            start = time.perf_counter()
            keypair = generate_keypair(bits=bits)
            keygen_times.append(time.perf_counter() - start)

        message = 42
        encrypt_times = []
        decrypt_times = []
        ciphertext = None
        for _ in range(trials_per_size):
            start = time.perf_counter()
            ciphertext = encrypt_int(message, keypair.public)
            encrypt_times.append(time.perf_counter() - start)

            start = time.perf_counter()
            decrypt_int(ciphertext, keypair.private)
            decrypt_times.append(time.perf_counter() - start)

        results["bits"].append(bits)
        results["keygen_time"].append(sum(keygen_times) / len(keygen_times))
        results["encrypt_time"].append(sum(encrypt_times) / len(encrypt_times))
        results["decrypt_time"].append(sum(decrypt_times) / len(decrypt_times))

        print(f"  avg keygen: {results['keygen_time'][-1]*1000:.2f} ms   "
              f"avg encrypt: {results['encrypt_time'][-1]*1000:.4f} ms   "
              f"avg decrypt: {results['decrypt_time'][-1]*1000:.4f} ms")

    return results


def plot_results(results, output_path: str = "benchmark_results.png"):
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(13, 5))
    fig.suptitle("RSA Performance vs. Key Size", fontsize=14, fontweight="bold")

    bits = results["bits"]

    ax1.plot(bits, [t * 1000 for t in results["keygen_time"]],
              marker="o", color="#2ecc71", linewidth=2, label="Key generation")
    ax1.set_xlabel("Prime bit length")
    ax1.set_ylabel("Time (ms)")
    ax1.set_title("Key Generation Time")
    ax1.grid(True, alpha=0.3)
    ax1.legend()

    ax2.plot(bits, [t * 1000 for t in results["encrypt_time"]],
              marker="o", color="#3498db", linewidth=2, label="Encryption (public, e=65537)")
    ax2.plot(bits, [t * 1000 for t in results["decrypt_time"]],
              marker="s", color="#e74c3c", linewidth=2, label="Decryption (private, full d)")
    ax2.set_xlabel("Prime bit length")
    ax2.set_ylabel("Time (ms)")
    ax2.set_title("Encryption vs. Decryption Time")
    ax2.grid(True, alpha=0.3)
    ax2.legend()

    plt.tight_layout()
    plt.savefig(output_path, dpi=150)
    print(f"\nSaved chart to {output_path}")


if __name__ == "__main__":
    bit_sizes = [128, 256, 384, 512, 768, 1024]
    results = benchmark_keysize(bit_sizes, trials_per_size=3)
    plot_results(results, output_path="security_analysis/benchmark_results.png")
