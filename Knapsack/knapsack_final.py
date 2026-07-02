import socket

HOST = "98.94.69.132"
PORT = 32442
TIMEOUT = 10


def knapsack(items, capacity):
    """
    Resolve o problema da mochila 0/1.
    Retorna (valor_máximo, lista_de_índices_dos_itens_selecionados).
    """
    n = len(items)
    dp = [[0] * (capacity + 1) for _ in range(n + 1)]

    for i in range(1, n + 1):
        w, v = items[i - 1]
        for c in range(capacity + 1):
            if w <= c:
                dp[i][c] = max(dp[i - 1][c], dp[i - 1][c - w] + v)
            else:
                dp[i][c] = dp[i - 1][c]

    # Reconstruir quais itens foram escolhidos
    c = capacity
    escolhidos = []
    for i in range(n, 0, -1):
        if dp[i][c] != dp[i - 1][c]:
            escolhidos.append(i - 1)
            c -= items[i - 1][0]
    escolhidos.reverse()
    return dp[n][capacity], escolhidos


def main():
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(TIMEOUT)
            print(f"[+] Conectando a {HOST}:{PORT} ...")
            s.connect((HOST, PORT))
            print("[+] Conectado!")

            # Cria um buffer para ler linhas facilmente
            f = s.makefile('r')

            # Lê e exibe a mensagem inicial (banner)
            banner = f.readline()
            if banner:
                print("\n[Servidor]")
                print(banner.strip())

            # Resolve 100 problemas
            for rodada in range(1, 101):
                # Lê a linha com "N W"
                linha = f.readline()
                if not linha:
                    print("[!] Servidor encerrou a conexão antes do esperado.")
                    break

                partes = linha.split()
                if len(partes) != 2 or not partes[0].isdigit() or not partes[1].isdigit():
                    # Pode ser uma mensagem de sucesso/fim
                    print("\n[Resposta final]")
                    print(linha.strip())
                    # Lê o restante que ainda possa existir
                    resto = f.read()
                    if resto:
                        print(resto.strip())
                    break

                n, W = map(int, partes)
                items = []
                for _ in range(n):
                    linha_item = f.readline()
                    if not linha_item:
                        break
                    w, v = map(int, linha_item.split())
                    items.append((w, v))

                # Resolve o problema
                _, indices = knapsack(items, W)
                resposta = ' '.join(map(str, indices))

                # Envia a solução
                s.sendall((resposta + '\n').encode())
                print(f"[{rodada:3d}] Enviado: {resposta}")

            # Após o loop, exibe qualquer mensagem final
            try:
                resto = f.read()
                if resto:
                    print("\n[Resposta final]")
                    print(resto.strip())
            except:
                pass

    except Exception as e:
        print(f"[ERRO] {e}")


if __name__ == "__main__":
    main()