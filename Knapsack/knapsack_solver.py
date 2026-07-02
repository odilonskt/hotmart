import socket
import json

HOST = "98.94.69.132"
PORT = 32442
TIMEOUT = 15

def knapsack_value(values, weights, capacity):
    """Retorna o valor máximo que cabe na mochila."""
    n = len(values)
    dp = [[0] * (capacity + 1) for _ in range(n + 1)]

    for i in range(1, n + 1):
        w = weights[i - 1]
        v = values[i - 1]
        for c in range(capacity + 1):
            if w <= c:
                dp[i][c] = max(dp[i - 1][c], dp[i - 1][c - w] + v)
            else:
                dp[i][c] = dp[i - 1][c]

    return dp[n][capacity]

def ler_json_do_socket(f):
    """Lê do socket até encontrar um JSON completo."""
    buffer = ""
    while True:
        linha = f.readline()
        if not linha:
            raise EOFError("Conexão encerrada")
        buffer += linha
        inicio = buffer.find('{')
        if inicio == -1:
            continue
        try:
            json_str = buffer[buffer.find('{'):]
            return json.loads(json_str)
        except json.JSONDecodeError:
            continue

def main():
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(TIMEOUT)
            print(f"[+] Conectando a {HOST}:{PORT} ...")
            s.connect((HOST, PORT))
            print("[+] Conectado!")

            # Força encoding UTF-8 e ignora caracteres inválidos (banner com arte ASCII)
            f = s.makefile('r', encoding='utf-8', errors='ignore')

            # Lê o banner inicial
            banner = ""
            while True:
                linha = f.readline()
                if not linha:
                    break
                banner += linha
                if "KNAPSACK" in linha:
                    break
            print("[Banner]")
            print(banner.strip())

            # Resolve 100 problemas
            for rodada in range(1, 101):
                try:
                    problema = ler_json_do_socket(f)
                except EOFError:
                    print("[!] Servidor fechou a conexão.")
                    break

                capacity = problema["capacity"]
                values = problema["values"]
                weights = problema["weights"]

                print(f"\n[Rodada {rodada}] Capacidade: {capacity}, Itens: {len(values)}")

                max_val = knapsack_value(values, weights, capacity)
                resposta = str(max_val)

                s.sendall((resposta + '\n').encode())
                print(f"[Enviado] {resposta}")

                confirmacao = f.readline()
                if confirmacao:
                    print(f"[Servidor] {confirmacao.strip()}")
                else:
                    print("[!] Sem resposta do servidor.")
                    break

            # Exibe a mensagem final (possível flag)
            resto = f.read()
            if resto:
                print("\n[Resposta final]")
                print(resto.strip())

    except Exception as e:
        print(f"[ERRO] {e}")

if __name__ == "__main__":
    main()