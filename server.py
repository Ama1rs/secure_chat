# server.py
# TLS-style demo server: accepts persistent connections, completes RSA handshake,
# and keeps the session until client disconnects or server is stopped.

import socket
import threading
import time
import os
import json
import base64
from cryptography.hazmat.primitives import serialization, hashes, hmac
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# -------------------------
# Helper crypto functions
# -------------------------
def generate_rsa_keypair(bits=2048):
    private = rsa.generate_private_key(public_exponent=65537, key_size=bits)
    return private

def rsa_public_pem(private_key):
    pub = private_key.public_key()
    return pub.public_bytes(encoding=serialization.Encoding.PEM,
                            format=serialization.PublicFormat.SubjectPublicKeyInfo)

def rsa_private_pem(private_key):
    return private_key.private_bytes(encoding=serialization.Encoding.PEM,
                                     format=serialization.PrivateFormat.PKCS8,
                                     encryption_algorithm=serialization.NoEncryption())

def rsa_decrypt(privkey, ciphertext):
    return privkey.decrypt(ciphertext,
                            padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                         algorithm=hashes.SHA256(),
                                         label=None))

def verify_signature(pub_pem, message, signature):
    pub = serialization.load_pem_public_key(pub_pem)
    try:
        pub.verify(signature,
                   message,
                   padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
                   hashes.SHA256())
        return True
    except Exception:
        return False

def aes_decrypt(key, iv, ciphertext):
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    pt_padded = decryptor.update(ciphertext) + decryptor.finalize()
    pad_len = pt_padded[-1]
    return pt_padded[:-pad_len]

def hmac_verify(key, data, tag):
    h = hmac.HMAC(key, hashes.SHA256())
    h.update(data)
    try:
        h.verify(tag)
        return True
    except Exception:
        return False

# -------------------------
# Server state & logging
# -------------------------
HOST = "127.0.0.1"
PORT = 5555
clients = {}           # conn -> state dict
clients_lock = threading.Lock()
logs = []
_server_socket = None
_server_thread = None
_server_running = threading.Event()

def log(msg):
    ts = time.strftime("%Y-%m-%d %H:%M:%S")
    entry = f"[{ts}] {msg}"
    print(entry)
    logs.append(entry)
    if len(logs) > 2000:
        del logs[:len(logs)-2000]

# -------------------------
# RSA key (persisted)
# -------------------------
SERVER_KEY_PATH = "server_key.pem"
if os.path.exists(SERVER_KEY_PATH):
    with open(SERVER_KEY_PATH, "rb") as f:
        server_private = serialization.load_pem_private_key(f.read(), password=None)
else:
    server_private = generate_rsa_keypair()
    with open(SERVER_KEY_PATH, "wb") as f:
        f.write(rsa_private_pem(server_private))

server_public_pem = rsa_public_pem(server_private)

# -------------------------
# Low-level receive helper
# -------------------------
def recv_all_until_double_newline(conn, timeout=10):
    buf = b""
    conn.settimeout(timeout)
    try:
        while True:
            chunk = conn.recv(4096)
            if not chunk:
                break
            buf += chunk
            if b"\n\n" in buf:
                before, rest = buf.split(b"\n\n", 1)
                return before
    except socket.timeout:
        return None
    except Exception:
        return None
    return buf if buf else None

# -------------------------
# Per-connection handler
# -------------------------
def handle_conn(conn, addr):
    log(f"Connection from {addr}")
    try:
        # Step 1: send server public key (PEM)
        conn.sendall(b"SERVER_PUB\n" + server_public_pem + b"\n\n")

        # Step 2: Expect encrypted session (base64 JSON) from client
        data = recv_all_until_double_newline(conn, timeout=10)
        if not data:
            log(f"{addr} closed before handshake")
            conn.close()
            return

        try:
            payload = json.loads(data.decode())
            enc_session_b64 = payload.get("enc_session")
            client_pub_b64 = payload.get("client_pub")
            client_sig_b64 = payload.get("client_sig")
        except Exception as e:
            log(f"Bad handshake payload from {addr}: {e}")
            conn.close()
            return

        enc_session = base64.b64decode(enc_session_b64)
        client_pub_pem = base64.b64decode(client_pub_b64)
        client_sig = base64.b64decode(client_sig_b64)

        # decrypt AES session blob
        try:
            session_blob = rsa_decrypt(server_private, enc_session)  # AESKEY||IV
        except Exception as e:
            log(f"Failed to decrypt session for {addr}: {e}")
            conn.close()
            return

        if len(session_blob) < 48:
            log(f"Session blob too short from {addr}")
            conn.close()
            return

        aes_key = session_blob[:32]
        aes_iv = session_blob[32:48]

        # verify client signature over the session blob
        if not verify_signature(client_pub_pem, session_blob, client_sig):
            log(f"Client signature verification failed for {addr}")
            conn.close()
            return

        log(f"Handshake completed with {addr}. AES session established (persistent).")

        with clients_lock:
            clients[conn] = {"addr": addr, "aes_key": aes_key, "aes_iv": aes_iv, "client_pub": client_pub_pem}

        # persistently accept encrypted messages until connection closes
        while True:
            msg = recv_all_until_double_newline(conn, timeout=None)
            if not msg:
                break
            try:
                m = json.loads(msg.decode())
                cipher_b = base64.b64decode(m["cipher"])
                tag_b = base64.b64decode(m["hmac"])
            except Exception:
                log(f"Malformed encrypted message from {addr}")
                break

            if not hmac_verify(aes_key, cipher_b, tag_b):
                log(f"HMAC verification failed from {addr}")
                break

            try:
                pt = aes_decrypt(aes_key, aes_iv, cipher_b)
                txt = pt.decode(errors='replace')
                log(f"From {addr}: {txt}")
            except Exception as e:
                log(f"Decrypt error from {addr}: {e}")
                break

    finally:
        with clients_lock:
            if conn in clients:
                del clients[conn]
        try:
            conn.shutdown(socket.SHUT_RDWR)
        except Exception:
            pass
        try:
            conn.close()
        except:
            pass
        log(f"Disconnected {addr}")

# -------------------------
# Server main loop
# -------------------------
def start_server(bind_host=HOST, bind_port=PORT):
    global _server_socket, _server_thread, _server_running
    if _server_running.is_set():
        log("Server already running")
        return

    def _serve():
        global _server_socket
        _server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        _server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            _server_socket.bind((bind_host, bind_port))
            _server_socket.listen(5)
            log(f"Server listening on {bind_host}:{bind_port}")
            _server_running.set()
            while _server_running.is_set():
                try:
                    _server_socket.settimeout(1.0)
                    conn, addr = _server_socket.accept()
                    t = threading.Thread(target=handle_conn, args=(conn, addr), daemon=True)
                    t.start()
                except socket.timeout:
                    continue
                except OSError:
                    break
        except Exception as e:
            log(f"Server error: {e}")
        finally:
            try:
                _server_socket.close()
            except:
                pass
            _server_running.clear()
            log("Server stopped")

    _server_thread = threading.Thread(target=_serve, daemon=True)
    _server_thread.start()
    return _server_thread

def stop_server():
    global _server_socket, _server_running
    if not _server_running.is_set():
        log("Server not running")
        return
    _server_running.clear()
    # close listening socket to unblock accept
    try:
        _server_socket.close()
    except:
        pass

if __name__ == "__main__":
    start_server()
    # keep main thread alive
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        stop_server()
