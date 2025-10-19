import socket
import threading

# Server configuration
HOST = '127.0.0.1'   # localhost
PORT = 5555          # any free port

# Create TCP socket
server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind((HOST, PORT))
server.listen()

print(f"[+] Server started on {HOST}:{PORT}")
clients = []

def handle_client(conn, addr):
    print(f"[+] New connection: {addr}")
    while True:
        try:
            msg = conn.recv(1024).decode()
            if not msg:
                break
            print(f"{addr}: {msg}")
        except:
            break
    print(f"[-] Disconnected: {addr}")
    conn.close()

def broadcast():
    while True:
        msg = input()
        for c in clients:
            try:
                c.send(msg.encode())
            except:
                clients.remove(c)

while True:
    conn, addr = server.accept()
    clients.append(conn)
    threading.Thread(target=handle_client, args=(conn, addr), daemon=True).start()
    threading.Thread(target=broadcast, daemon=True).start()
