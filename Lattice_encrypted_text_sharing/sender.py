# sender_app.py
import streamlit as st
import asyncio
import websockets
import matrixzq as mq
import discrete_gaussian_zq as dgz
import random
import pickle
import hashlib
import time
from pathlib import Path

# Constants
MAX_MESSAGE_SIZE = 1024
DEBUG = False
DPRINT = print if DEBUG else lambda *a, **k: None

def compute_sha256_hash(data):
    """Compute the SHA-256 hash of the given data."""
    sha256_hash = hashlib.sha256()
    sha256_hash.update(data.encode('utf-8'))
    return sha256_hash.hexdigest()

def text_to_bits(text):
    """Convert text to a binary string (UTF-8 encoded)."""
    return ''.join(format(ord(char), '08b') for char in text)

async def encrypt_and_send(message, progress_bar, status_text):
    """Handle encryption and sending messages to the receiver."""
    q = 31  # Modulus
    n = 4   # Security parameter
    N = 7   # LWE sample size
    sigma = 1.0

    mq.set_modulus(q)
    
    start_time = time.perf_counter()

    # Key Generation
    status_text.text("Generating keys...")
    s = mq.new_vector([mq.random_element() for _ in range(n)])
    A = mq.new_matrix([[mq.random_element() for _ in range(n)] for _ in range(N)])
    dgi = dgz.Dgi(q, sigma=sigma)
    e = mq.new_vector([dgi.D() for _ in range(N)])
    b = mq.multiply(A, s)
    b = mq.add(b, e)

    # Compute SHA-256 hash of the input message
    input_hash = compute_sha256_hash(message)
    status_text.text("Computing message hash...")
    progress_bar.progress(0.2)

    bits = text_to_bits(message)
    encrypted_bits = []

    # Encryption
    status_text.text("Encrypting message...")
    total_bits = len(bits)
    for idx, bit in enumerate(bits):
        m = int(bit)
        r = mq.new_vector([random.randint(0, 1) for _ in range(N)])
        u = mq.multiply(mq.transpose(A), r)
        qm2 = (q // 2) * m
        v = mq.dotproduct(b, r) + qm2
        encrypted_bits.append((u, v))
        progress_bar.progress(0.2 + 0.4 * (idx / total_bits))

    # Send encrypted data
    status_text.text("Sending encrypted data...")
    encrypted_data = pickle.dumps((encrypted_bits, A, b, s, input_hash))
    
    try:
        async with websockets.connect('ws://localhost:6789') as websocket:
            total_chunks = (len(encrypted_data) + MAX_MESSAGE_SIZE - 1) // MAX_MESSAGE_SIZE
            for i in range(0, len(encrypted_data), MAX_MESSAGE_SIZE):
                chunk = encrypted_data[i:i + MAX_MESSAGE_SIZE]
                await websocket.send(chunk)
                progress_bar.progress(0.6 + 0.4 * (i / len(encrypted_data)))
            await websocket.send(b'END')
            
        encryption_time = time.perf_counter() - start_time
        status_text.text("✅ Encryption and transmission complete!")
        progress_bar.progress(1.0)
        return True, encryption_time, input_hash
        
    except Exception as e:
        status_text.error(f"Error during transmission: {str(e)}")
        return False, 0, input_hash

def main():
    st.title("LWE Encryption Sender")
    st.write("This application encrypts and sends messages using Lattice-based encryption.")

    # File upload
    uploaded_file = st.file_uploader("Choose a text file to encrypt", type=['txt'])
    
    if uploaded_file is not None:
        message = uploaded_file.getvalue().decode('utf-8')
        st.write(f"File loaded: {len(message)} characters")
        
        if st.button("Encrypt and Send"):
            progress_bar = st.progress(0)
            status_text = st.empty()
            
            # Run the encryption and sending process
            success, encryption_time, input_hash = asyncio.run(
                encrypt_and_send(message, progress_bar, status_text)
            )
            
            if success:
                st.success("Message sent successfully!")
                st.write(f"Encryption time: {encryption_time:.2f} seconds")
                st.write(f"Message hash: {input_hash}")
            else:
                st.error("Failed to send message. Please ensure the receiver is running.")

if __name__ == "__main__":
    main()