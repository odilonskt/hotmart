import socket
import re
import time

HOST = "98.94.69.132"
PORT = 32442


def recv_all(sock, timeout=8.0, max_bytes=20_000_000):
    sock.settimeout(0.5)
    buf = bytearray()
    start = time.time()
    while True:
        if time.time() - start > timeout:
            break
        try:
            chunk = sock.recv(8192)
            if not chunk:
                break
            buf += chunk
            if len(buf) >= max_bytes:
                break
        except socket.timeout:
            continue
    return bytes(buf)


def main():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((HOST, PORT))

        data = recv_all(s, timeout=12.0)
        txt = data.decode(errors="ignore")

        print(txt)

        # também salva em arquivo para você colar aqui com facilidade
        out_path = "Knapsack/last_server_prompt.txt"
        try:
            with open(out_path, "w", encoding="utf-8", errors="ignore") as f:
                f.write(txt)
            print(f"\n[+] Salvo em: {out_path}")
        except Exception:
            pass


if __name__ == "__main__":
    main()

