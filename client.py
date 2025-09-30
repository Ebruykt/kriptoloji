import socket
import os

HOST = "127.0.0.1"
PORT = 12345

client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client_socket.connect((HOST, PORT))

filename = "odev.mp4"  # göndereceğin video dosyası
filesize = os.path.getsize(filename)

# önce dosya bilgisi gönder
client_socket.send(f"{filename}|{filesize}".encode())
ack = client_socket.recv(1024).decode()  # server’dan onay bekle

# dosyayı binary modda aç ve gönder
with open(filename, "rb") as f:
    while True:
        bytes_read = f.read(4096)  # 4KB parça
        if not bytes_read:
            break
        client_socket.sendall(bytes_read)

print("Video gönderildi ✅")
client_socket.close()
