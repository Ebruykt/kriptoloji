import socket

HOST = "127.0.0.1"
PORT = 12345

server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind((HOST, PORT))
server_socket.listen()

print("Sunucu dinleniyor...")
conn, addr = server_socket.accept()
print("Bağlanan:", addr)

# önce dosya bilgisi al
file_info = conn.recv(1024).decode()
filename, filesize = file_info.split("|")
filesize = int(filesize)
conn.send("OK".encode())  # client’a onay gönder

# dosya kaydet
with open("gelen_" + filename, "wb") as f:
    bytes_received = 0
    while bytes_received < filesize:
        data = conn.recv(4096)
        if not data:
            break
        f.write(data)
        bytes_received += len(data)

print("Video başarıyla kaydedildi ✅")
conn.close()
server_socket.close()
