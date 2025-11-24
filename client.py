# client.py
# Client with persistent connection: can connect/handshake and send many messages
# over a persistent socket until disconnected.

import socket
import json
import base64
import os
from cryptography.hazmat.primitives import serialization, hashes, hmac
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import threading
import time

# -------------------------
# Crypto helpers
# -------------------------
def generate_rsa_keypair(bits=2048):
    return rsa.generate_private_key(public_exponent=65537, key_size=bits)

def rsa_encrypt(pub_pem, message):
    pub = serialization.load_pem_public_key(pub_pem)
    return pub.encrypt(message,
                       padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                    algorithm=hashes.SHA256(), label=None))

def rsa_sign(priv, message):
    return priv.sign(message,
                     padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
                     hashes.SHA256())

def aes_encrypt(key, iv, plaintext):
    pad_len = 16 - (len(plaintext) % 16)
    padded = plaintext + bytes([pad_len]) * pad_len
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    enc = cipher.encryptor()
    return enc.update(padded) + enc.finalize()

def hmac_create(key, data):
    h = hmac.HMAC(key, hashes.SHA256())
    h.update(data)
    return h.finalize()

# -------------------------
# Client operations (persistent)
# -------------------------
def connect_and_handshake(host="127.0.0.1", port=5555, client_priv=None):
    """
    Connect to server, complete handshake, return (socket, aes_key, aes_iv, client_priv)
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((host, port))

    # receive server public PEM chunk
    buf = b""
    while True:
        chunk = s.recv(4096)
        if not chunk:
            s.close()
            raise RuntimeError("Connection closed while waiting for server pub")
        buf += chunk
        if b"\n\n" in buf:
            header, rest = buf.split(b"\n\n", 1)
            break

    if not header.startswith(b"SERVER_PUB\n"):
        s.close()
        raise RuntimeError("Bad server header")
    server_pem = header.split(b"\n",1)[1]

    # ensure client keys exist
    if client_priv is None:
        client_priv = generate_rsa_keypair()
    client_pub_pem = client_priv.public_key().public_bytes(encoding=serialization.Encoding.PEM,
                                                           format=serialization.PublicFormat.SubjectPublicKeyInfo)

    # ephemeral AES session
    aes_key = os.urandom(32)
    aes_iv = os.urandom(16)
    session_blob = aes_key + aes_iv

    enc_session = rsa_encrypt(server_pem, session_blob)
    client_sig = rsa_sign(client_priv, session_blob)

    payload = {
        "enc_session": base64.b64encode(enc_session).decode(),
        "client_pub": base64.b64encode(client_pub_pem).decode(),
        "client_sig": base64.b64encode(client_sig).decode()
    }
    s.sendall(json.dumps(payload).encode() + b"\n\n")

    # successful handshake — return persistent socket
    return s, aes_key, aes_iv, client_priv

def send_message(socket_obj, aes_key, aes_iv, text):
    ciphertext = aes_encrypt(aes_key, aes_iv, text.encode())
    tag = hmac_create(aes_key, ciphertext)  # demo uses aes_key for HMAC
    msg = {"cipher": base64.b64encode(ciphertext).decode(), "hmac": base64.b64encode(tag).decode()}
    socket_obj.sendall(json.dumps(msg).encode() + b"\n\n")

def close_socket(s):
    try:
        s.shutdown(socket.SHUT_RDWR)
    except:
        pass
    try:
        s.close()
    except:
        pass

# For debugging/demo: local client that connects, keeps session, and sends messages periodically
if __name__ == "__main__":
    s, k, iv, priv = connect_and_handshake()
    for i in range(5):
        send_message(s, k, iv, f"hello {i}")
        time.sleep(1)
    close_socket(s)
