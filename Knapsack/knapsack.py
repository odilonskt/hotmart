import socket

HOST = "98.94.69.132"
PORT = 32442

try:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(10)  # timeout de 10 segundos

        print(f"[+] Conectando em {HOST}:{PORT}...")
        s.connect((HOST, PORT))
        print("[+] Conectado!")

        # Recebe a mensagem inicial do servidor
        data = s.recv(4096)
        if data:
            print("\n[Servidor]")
            print(data.decode(errors="ignore"))

        # Loop interativo
        while True:
            msg = input("\n> ")
            if not msg:
                break

            s.sendall(msg.encode() + b"\n")

            resposta = s.recv(4096)
            if not resposta:
                print("[!] Conexão encerrada pelo servidor.")
                break

            print("\n[Resposta]")
            print(resposta.decode(errors="ignore"))

except Exception as e:
    print(f"[ERRO] {e}")