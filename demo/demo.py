"""
demo.py
-------
Run with:
    python3 -m demo.demo
"""

import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from rich.console import Console
from rich.panel import Panel
from rich.progress import (
    BarColumn,
    Progress,
    SpinnerColumn,
    TextColumn,
    TimeElapsedColumn,
)
from rich.prompt import Prompt
from rich.table import Table
from rich.text import Text

from rsa_crypto.cipher import decrypt_message, encrypt_message
from rsa_crypto.keygen import generate_keypair

console = Console()


def show_banner():
    banner = Text()
    banner.append("  RSA ", style="bold bright_green")
    banner.append("CRYPTOSYSTEM", style="bold white")
    banner.append("  ", style="bold bright_green")
    console.print()
    console.print(Panel(banner, border_style="bright_green", expand=False))
    console.print(
        "[dim]A from-scratch implementation of public-key cryptography[/dim]\n"
    )


def run_key_generation(bits: int):
    with Progress(
        SpinnerColumn(style="bright_green"),
        TextColumn("[bold green]{task.description}"),
        BarColumn(bar_width=40, style="green", complete_style="bright_green"),
        TimeElapsedColumn(),
        console=console,
    ) as progress:
        task = progress.add_task(f"Generating {bits}-bit prime p...", total=100)
        for _ in range(20):
            time.sleep(0.04)
            progress.update(task, advance=5)

        progress.update(task, description=f"Generating {bits}-bit prime q...")
        for _ in range(20):
            time.sleep(0.04)
            progress.update(task, advance=5)

        progress.update(task, description="Deriving keys (n, e, d)...")

    keypair = generate_keypair(bits=bits)
    return keypair


def show_keys(keypair):
    table = Table(title="Generated Key Pair", border_style="bright_green", show_lines=False)
    table.add_column("Key", style="bold cyan")
    table.add_column("Value", style="green", overflow="fold")

    def truncate(n: int, head: int = 24, tail: int = 24) -> str:
        s = str(n)
        if len(s) <= head + tail + 3:
            return s
        return f"{s[:head]}...{s[-tail:]}  ({len(s)} digits)"

    table.add_row("Public  (n, e)", f"n = {truncate(keypair.public.n)}\ne = {keypair.public.e}")
    table.add_row("Private (n, d)", f"n = {truncate(keypair.private.n)}\nd = {truncate(keypair.private.d)}")

    console.print(table)
    console.print()


def animate_encryption(message: str, keypair):
    console.print(Panel(f"[bold white]{message}", title="Plaintext", border_style="cyan"))

    with console.status("[bold green]Encrypting with public key (m^e mod n)...", spinner="dots"):
        time.sleep(1.0)
        encrypted = encrypt_message(message, keypair.public)

    preview = ", ".join(str(b)[:20] + "..." if len(str(b)) > 20 else str(b) for b in encrypted[:3])
    if len(encrypted) > 3:
        preview += f", ... (+{len(encrypted) - 3} more block(s))"

    console.print(Panel(f"[bold yellow]{preview}", title=f"Ciphertext ({len(encrypted)} block(s))", border_style="yellow"))
    return encrypted


def animate_decryption(encrypted, keypair):
    with console.status("[bold green]Decrypting with private key (c^d mod n)...", spinner="dots"):
        time.sleep(1.0)
        decrypted = decrypt_message(encrypted, keypair.private)

    console.print(Panel(f"[bold white]{decrypted}", title="Decrypted Plaintext", border_style="bright_green"))
    return decrypted


def main():
    show_banner()

    bits = 256
    console.print(f"[dim]Key size: {bits} bits per prime (demo speed - see README for production sizing)[/dim]\n")

    console.print("[bold]Step 1:[/bold] Key Generation\n")
    keypair = run_key_generation(bits)
    show_keys(keypair)

    message = Prompt.ask(
        "[bold cyan]Step 2:[/bold cyan] Enter a message to encrypt",
        default="Hello from MBSTU! 🔐",
    )
    console.print()

    console.print("[bold]Step 3:[/bold] Encryption\n")
    encrypted = animate_encryption(message, keypair)
    console.print()

    console.print("[bold]Step 4:[/bold] Decryption\n")
    decrypted = animate_decryption(encrypted, keypair)
    console.print()

    success = (message == decrypted)
    status_style = "bold bright_green" if success else "bold red"
    status_text = "✓ Round-trip verified - message recovered exactly" if success else "✗ Mismatch detected"
    console.print(Panel(status_text, border_style="bright_green" if success else "red", style=status_style))


if __name__ == "__main__":
    main()
