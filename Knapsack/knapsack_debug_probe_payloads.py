import socket

HOST = "98.94.69.132"
PORT = 32442

payloads = [
    "",  # empty
    "0\n",
    "0\r\n",
    "0 ",
    "[0]",
    "[0,1]",
    "0 1",
    "0,1",
    "[0,1]\n",
    "0 1\n",
    "0,1\n",
    "[0, 1]",
    "[0, 1]\n",
]


def recv_some(s, timeout=1.0):
    s.settimeout(timeout)
    out = b""
    try:
        while True:
            chunk = s.recv(4096)
            if not chunk:
                break
            out += chunk
            if len(out) > 20000:
                break
    except Exception:
        pass
    return out


def main():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((HOST, PORT))
        print(recv_some(s, timeout=1.0).decode(errors="ignore"))

        # Envia cada payload após uma tentativa de coletar um JSON (pode travar se o servidor esperar
        # primeiro o challenge real; aqui é só um probe rápido do formato aceito).
        for p in payloads:
            print("\n--- enviando payload repr:", repr(p))
            if p is None:
                continue
            to_send = p.encode() if isinstance(p, str) else p
            s.sendall(to_send)
            print("[resposta]\n", recv_some(s, timeout=1.0).decode(errors="ignore"))


if __name__ == "__main__":
    main()

