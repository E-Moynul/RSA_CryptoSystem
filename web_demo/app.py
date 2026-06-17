"""
app.py
------
Interactive browser-based demo of the RSA cryptosystem, built with
Streamlit.
"""

import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import streamlit as st

from rsa_crypto.cipher import decrypt_message, encrypt_message
from rsa_crypto.keygen import generate_keypair

st.set_page_config(
    page_title="RSA Cryptosystem Demo",
    page_icon="🔐",
    layout="centered",
)

st.markdown(
    """
    <style>
    .stApp {
        background-color: #0d1117;
        color: #c9d1d9;
    }
    h1, h2, h3 {
        color: #39ff88 !important;
        font-family: 'Courier New', monospace;
    }
    .stButton>button {
        background-color: #0d1117;
        color: #39ff88;
        border: 1px solid #39ff88;
        font-family: 'Courier New', monospace;
    }
    .stButton>button:hover {
        background-color: #39ff88;
        color: #0d1117;
    }
    code {
        color: #5eead4 !important;
    }
    </style>
    """,
    unsafe_allow_html=True,
)

st.title("🔐 RSA Cryptosystem")
st.caption("A from-scratch RSA implementation - live in your browser")

st.markdown(
    "This demo generates **real RSA keys** in your browser session and "
    "encrypts/decrypts your message using the same engine that powers the "
    "[CLI demo and security analysis](https://github.com) in this project. "
    "Nothing here is mocked - the math runs live."
)

st.divider()

st.subheader("1. Generate a key pair")

bits = st.select_slider(
    "Prime bit length",
    options=[128, 256, 384, 512],
    value=256,
    help="Larger keys are more secure but slower to generate. 512 bits "
         "per prime gives a 1024-bit modulus, kept here for demo speed - "
         "real-world RSA uses 2048+ bit moduli.",
)

if "keypair" not in st.session_state:
    st.session_state.keypair = None

if st.button("Generate New Key Pair", type="primary"):
    with st.spinner(f"Generating {bits}-bit primes..."):
        start = time.perf_counter()
        st.session_state.keypair = generate_keypair(bits=bits)
        elapsed = time.perf_counter() - start
    st.success(f"Key pair generated in {elapsed*1000:.1f} ms")

if st.session_state.keypair:
    kp = st.session_state.keypair

    def truncate(n: int, head: int = 30, tail: int = 30) -> str:
        s = str(n)
        if len(s) <= head + tail + 3:
            return s
        return f"{s[:head]}...{s[-tail:]}"

    col1, col2 = st.columns(2)
    with col1:
        st.markdown("**Public Key**")
        st.code(f"n = {truncate(kp.public.n)}\ne = {kp.public.e}", language="text")
    with col2:
        st.markdown("**Private Key**")
        st.code(f"n = {truncate(kp.private.n)}\nd = {truncate(kp.private.d)}", language="text")

    st.divider()

    st.subheader("2. Encrypt a message")
    message = st.text_input(
        "Your message",
        value="Hello from MBSTU!",
        help="Supports full UTF-8, including Bangla and emoji.",
    )

    if message:
        try:
            encrypted = encrypt_message(message, kp.public)

            st.markdown("**Ciphertext blocks:**")
            for i, block in enumerate(encrypted):
                st.code(f"Block {i+1}: {truncate(block, 25, 25)}", language="text")

            st.divider()

            st.subheader("3. Decrypt it back")
            decrypted = decrypt_message(encrypted, kp.private)
            st.code(decrypted, language="text")

            if decrypted == message:
                st.success("✓ Round-trip verified - message recovered exactly")
            else:
                st.error("✗ Mismatch - this shouldn't happen, please report it")

        except Exception as exc:
            st.error(f"Encryption failed: {exc}")
else:
    st.info("Click \"Generate New Key Pair\" above to get started.")

st.divider()
st.caption(
    "Built with a from-scratch RSA implementation (Miller-Rabin primality "
    "testing, Extended Euclidean Algorithm for key derivation). "
)
