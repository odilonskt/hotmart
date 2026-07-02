import socket
import re

HOST = "98.94.69.132"
PORT = 32442


def recv_some(s, timeout=12.0, max_bytes=12_000_000):
    s.settimeout(timeout)
    buf = bytearray()
    while True:
        try:
            chunk = s.recv(8192)
            if not chunk:
                break
            buf += chunk
            if len(buf) >= max_bytes:
                break
        except TimeoutError:
            break
    return bytes(buf)


def find_snippet(text: str, patterns, window=300):
    for pat in patterns:
        m = re.search(pat, text, re.IGNORECASE)
        if m:
            start = max(0, m.start() - window)
            end = min(len(text), m.end() + window)
            return text[start:end]
    return None


def main():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        print(f"[+] Conectando em {HOST}:{PORT}...")
        s.connect((HOST, PORT))
        print("[+] Conectado!")

        # 1) recebe banner+JSON (e talvez instruções)
        buf1 = recv_some(s, timeout=8.0, max_bytes=6_000_000)
        txt1 = buf1.decode(errors="ignore")
        print("\n=== BUF1 (primeira leitura) ===\n")
        print(txt1)

        # tenta identificar instruções já no buffer 1
        snippet1 = find_snippet(
            txt1,
            patterns=[r"monta\s+uma\s+matriz", r"envie", r"respon", r"matriz", r"até\s*100"],
            window=400,
        )
        if snippet1:
            print("\n=== SNIPPET (BUF1) ===\n")
            print(snippet1)

        # 2) envia dummy para destravar fluxo
        try:
            s.sendall(b"0\n")
        except Exception:
            pass

        # 3) recebe o que vier depois
        buf2 = recv_some(s, timeout=8.0, max_bytes=6_000_000)
        txt2 = buf2.decode(errors="ignore")
        print("\n=== BUF2 (depois de enviar 0) ===\n")
        print(txt2)

        snippet2 = find_snippet(
            txt2,
            patterns=[r"monta\s+uma\s+matriz", r"envie", r"respon", r"matriz", r"até\s*100"],
            window=500,
        )
        if snippet2:
            print("\n=== SNIPPET (BUF2) ===\n")
            print(snippet2)


if __name__ == "__main__":
    main()

