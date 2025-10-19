import socket
import threading

HOST = '127.0.0.1'   # same as server
PORT = 5555

client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.connect((HOST, PORT))

def receive():
    while True:
        try:
            msg = client.recv(1024).decode()
            if msg:
                print(f"\nServer: {msg}")
        except:
            print("[!] Connection closed by server.")
            break

def send():
    while True:
        msg = input()
        if msg.lower() == 'exit':
            client.close()
            break
        client.send(msg.encode())

threading.Thread(target=receive, daemon=True).start()
send()
