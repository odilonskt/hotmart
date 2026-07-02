import socket

HOST = "98.94.69.132"
PORT = 32442


def recv_until_timeout_or_flag(s, timeout=2.0, max_bytes=2_000_000):
    s.settimeout(timeout)
    buf = b""
    while True:
        try:
            chunk = s.recv(4096)
            if not chunk:
                break
            buf += chunk
            if len(buf) > max_bytes:
                break
            print(chunk.decode(errors="ignore"), end="")
            low = chunk.lower()
            if b"flag" in low:
                break
        except TimeoutError:
            break
    return buf


def main():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        print(f"[+] Conectando em {HOST}:{PORT}...")
        s.connect((HOST, PORT))
        print("[+] Conectado!")

        print("\n=== STREAM (primeira rodada/prompt) ===\n")
        recv_until_timeout_or_flag(s, timeout=12.0, max_bytes=10_000_000)

        # Envia um valor dummy para destravar o fluxo do servidor.
        try:
            s.sendall(b"0\n")
        except Exception:
            pass

        # Captura o texto que vier após a resposta do cliente.
        recv_until_timeout_or_flag(s, timeout=12.0, max_bytes=10_000_000)

        print("\n\n=== FIM DUMP ===")


if __name__ == "__main__":
    main()

