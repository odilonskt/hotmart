import socket

HOST = "98.94.69.132"
PORT = 32442


def main():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        print(f"[+] Conectando em {HOST}:{PORT}...")
        s.connect((HOST, PORT))
        print("[+] Conectado!")

        # Aguarda um pouco pra o servidor mandar o desafio.
        s.settimeout(2)

        buf = b""
        while True:
            try:
                data = s.recv(4096)
                if not data:
                    break
                buf += data
                print(data.decode(errors="ignore"), end="")

                # Se vier flag em qualquer parte, para.
                low = data.lower()
                if b"flag" in low:
                    break

            except TimeoutError:
                # Sem mais dados por um tempo: provavelmente fim do desafio/parada.
                if buf:
                    print("\n[+] Timeout sem mais dados; encerrando dump.")
                break


if __name__ == "__main__":
    main()

