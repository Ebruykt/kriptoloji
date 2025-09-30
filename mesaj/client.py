import socket

HOST = "127.0.0.1"  # server'ın IP'si
PORT = 12345

client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client_socket.connect((HOST, PORT))

while True:
    msg = input("Mesaj: ")
    client_socket.sendall(msg.encode())
    data = client_socket.recv(1024).decode()
    print("Sunucudan gelen:", data)
