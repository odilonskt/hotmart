import socket

HOST = "98.94.69.132"
PORT = 32443

try:
    print(f"[+] Conectando em {HOST}:{PORT}...")

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(5)
    s.connect((HOST, PORT))

    print("[+] Conectado!")

    # Recebe dados iniciais do servidor
    data = s.recv(4096)

    print(f"\n[+] Total bytes recebidos: {len(data)}")
    print("\n=== RAW TEXT ===\n")
    try:
        print(data.decode("utf-8", errors="replace"))
    except Exception:
        print(data)

    # Mantém interação manual
    while True:
        msg = input("\n> ")
        if msg.lower() in ("exit", "quit"):
            break

        s.sendall(msg.encode() + b"\n")

        response = s.recv(4096)
        print(response.decode("utf-8", errors="replace"))

    s.close()

except Exception as e:
    print(f"[-] Erro: {e}")