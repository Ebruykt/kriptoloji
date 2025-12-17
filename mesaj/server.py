"""
Basit TCP echo sunucusu (mesaj/client.py ile uyumlu)
"""
import socket

HOST = "127.0.0.1"
PORT = 12345


def main():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind((HOST, PORT))
    server_socket.listen(1)
    print(f"Sunucu dinliyor: {HOST}:{PORT}")

    try:
        while True:
            conn, addr = server_socket.accept()
            print(f"Bağlandı: {addr}")
            with conn:
                while True:
                    data = conn.recv(1024)
                    if not data:
                        break
                    msg = data.decode(errors="ignore")
                    print(f"Alındı: {msg}")
                    conn.sendall(f"ECHO: {msg}".encode())
            print(f"Bağlantı kapandı: {addr}")
    except KeyboardInterrupt:
        print("\nSunucu kapatılıyor...")
    finally:
        server_socket.close()


if __name__ == "__main__":
    main()

