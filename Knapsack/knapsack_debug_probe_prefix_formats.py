import socket

HOST = "98.94.69.132"
PORT = 32442

# payloads candidatos: contagem prefixada e variações
payloads = [
    # contagem -> lista
    "0\n0\n",
    "0\n0\n\n",
    "0\n",
    "0",

    "1\n0\n",
    "1\n0",
    "1 0",

    "2\n0 1\n",
    "2\n0,1\n",

    # lista vazia com diferentes formatos
    "[]\n",
    "[ ]\n",
    "[0]\n",
]


def recv_some(s, timeout=1.0, max_len=20000):
    s.settimeout(timeout)
    out = b""
    try:
        while True:
            chunk = s.recv(4096)
            if not chunk:
                break
            out += chunk
            if len(out) > max_len:
                break
    except Exception:
        pass
    return out


def main():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((HOST, PORT))
        # consome banner/primeira mensagem
        _ = recv_some(s, timeout=1.0)

        for p in payloads:
            print("\n--- enviando ---")
            print("repr:", repr(p))
            try:
                s.sendall(p.encode())
            except Exception as e:
                print("send error:", e)
                break
            resp = recv_some(s, timeout=1.2)
            if resp:
                print(resp.decode(errors="ignore"))
            else:
                print("[resposta vazia]")


if __name__ == "__main__":
    main()

