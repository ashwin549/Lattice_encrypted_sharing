# receiver_app.py
import streamlit as st
import asyncio
import websockets
import matrixzq as mq
import pickle
import hashlib
from pathlib import Path

def compute_sha256_hash(data):
    """Compute the SHA-256 hash of the given data."""
    sha256_hash = hashlib.sha256()
    sha256_hash.update(data.encode('utf-8'))
    return sha256_hash.hexdigest()

def bits_to_text(bits):
    """Convert binary string back to text (UTF-8 encoded)."""
    chars = []
    for i in range(0, len(bits), 8):
        byte = bits[i:i+8]
        chars.append(chr(int(byte, 2)))
    return ''.join(chars)

class DecryptionServer:
    def __init__(self, progress_bar, status_text, result_container):
        self.progress_bar = progress_bar
        self.status_text = status_text
        self.result_container = result_container
        self.received_data = False
        
    async def decrypt_message(self, websocket, path):
        self.status_text.text("Receiving encrypted data...")
        encrypted_data = b''
        
        while True:
            try:
                chunk = await websocket.recv()
                if chunk == b'END':
                    break
                encrypted_data += chunk
                self.progress_bar.progress(min(0.5, len(encrypted_data) / 1000000))  # Approximate progress
            except websockets.ConnectionClosed:
                break

        self.status_text.text("Decrypting message...")
        encrypted_bits, A, b, s, input_hash = pickle.loads(encrypted_data)

        # Perform decryption
        q = 31  # Modulus
        mq.set_modulus(q)
        decrypted_bits = []

        for idx, (u, v) in enumerate(encrypted_bits):
            v1 = mq.dotproduct(u, s)
            d = v - v1
            decrypted_bit = mq.roundfrac2int(2 * d, q) % 2
            decrypted_bits.append(str(decrypted_bit))
            self.progress_bar.progress(0.5 + 0.5 * (idx / len(encrypted_bits)))

        decrypted_message = bits_to_text(''.join(decrypted_bits))
        decrypted_hash = compute_sha256_hash(decrypted_message)

        # Update the Streamlit UI with results
        with self.result_container:
            st.write("### Decryption Results")
            st.write(f"Original message hash: {input_hash}")
            st.write(f"Decrypted message hash: {decrypted_hash}")
            
            if input_hash == decrypted_hash:
                st.success("✅ Verification successful: The decrypted message matches the original!")
            else:
                st.error("❌ Verification failed: The decrypted message does not match the original.")
            
            # Save decrypted message
            save_path = Path("decrypted_output.txt")
            save_path.write_text(decrypted_message, encoding='utf-8')
            
            st.write("### Decrypted Message Preview")
            st.text_area("Preview", value=decrypted_message[:1000] + 
                        ("..." if len(decrypted_message) > 1000 else ""), 
                        height=200)
            
            st.download_button(
                label="Download Decrypted Message",
                data=decrypted_message,
                file_name="decrypted_output.txt",
                mime="text/plain"
            )

        self.status_text.text("✅ Decryption complete!")
        self.progress_bar.progress(1.0)
        self.received_data = True

async def run_server(progress_bar, status_text, result_container):
    server = DecryptionServer(progress_bar, status_text, result_container)
    async with websockets.serve(server.decrypt_message, "localhost", 6789):
        while not server.received_data:
            await asyncio.sleep(0.1)

def main():
    st.title("LWE Encryption Receiver")
    st.write("This application receives and decrypts messages using Lattice-based encryption.")

    if 'server_running' not in st.session_state:
        st.session_state.server_running = False

    if not st.session_state.server_running:
        if st.button("Start Receiver"):
            st.session_state.server_running = True
            progress_bar = st.progress(0)
            status_text = st.empty()
            result_container = st.container()
            
            status_text.text("Waiting for incoming messages...")
            
            try:
                asyncio.run(run_server(progress_bar, status_text, result_container))
            except Exception as e:
                st.error(f"Error: {str(e)}")
                st.session_state.server_running = False
    else:
        st.info("Receiver is running. Waiting for incoming messages...")
        if st.button("Stop Receiver"):
            st.session_state.server_running = False
            st.experimental_rerun()

if __name__ == "__main__":
    main()