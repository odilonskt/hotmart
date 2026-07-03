import socket
import json
import re

def dijkstra_matriz(S, F, adj):
    n = len(adj)
    INF = float('inf')
    dist = [INF] * n
    prev = [-1] * n
    dist[S] = 0
    visitado = [False] * n

    for _ in range(n):
        u = -1
        menor = INF
        for i in range(n):
            if not visitado[i] and dist[i] < menor:
                menor = dist[i]
                u = i
        if u == -1 or u == F:
            break
        visitado[u] = True
        for v in range(n):
            if not visitado[v] and adj[u][v] < INF:
                nova = dist[u] + adj[u][v]
                if nova < dist[v]:
                    dist[v] = nova
                    prev[v] = u

    if dist[F] == INF:
        return None, None

    caminho = []
    atual = F
    while atual != -1:
        caminho.append(atual)
        if atual == S:
            break
        atual = prev[atual]
    if caminho[-1] != S:
        return None, None
    caminho.reverse()
    return caminho, dist[F]

def redimensionar_adj(adj, novo_n):
    n = len(adj)
    if novo_n <= n:
        return adj
    INF = float('inf')
    for i in range(n):
        adj[i].extend([INF] * (novo_n - n))
    for _ in range(novo_n - n):
        adj.append([INF] * novo_n)
    return adj

def main():
    HOST = '98.94.69.132'
    PORT = 32445

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((HOST, PORT))
    sock.settimeout(5.0)

    buffer = ""
    adj = None
    S = F = None

    while True:
        try:
            dados = sock.recv(4096).decode('utf-8', errors='ignore')
            if not dados:
                print("Conexão encerrada pelo servidor.")
                break

            buffer += dados

            while '\n' in buffer:
                linha, buffer = buffer.split('\n', 1)
                linha = linha.strip()
                if not linha:
                    continue

                # Flag?
                if 'flag{' in linha.lower():
                    print("\n🏁 FLAG ENCONTRADA 🏁")
                    print(linha)
                    sock.close()
                    return

                # JSON (GRAPH_INIT)
                if linha.startswith('{'):
                    try:
                        obj = json.loads(linha)
                        grafo = None
                        if 'GRAPH_INIT' in obj:
                            grafo = obj['GRAPH_INIT']
                        elif 'S' in obj and 'F' in obj and 'EDGES' in obj:
                            grafo = obj
                        else:
                            for v in obj.values():
                                if isinstance(v, dict) and 'S' in v and 'F' in v and 'EDGES' in v:
                                    grafo = v
                                    break
                        if grafo:
                            S = grafo['S']
                            F = grafo['F']
                            edges = grafo['EDGES']
                            max_no = 0
                            for u, v, _ in edges:
                                max_no = max(max_no, u, v)
                            n = max_no + 1
                            INF = float('inf')
                            adj = [[INF] * n for _ in range(n)]
                            for u, v, w in edges:
                                if w < adj[u][v]:
                                    adj[u][v] = w
                                    adj[v][u] = w
                            # Resposta inicial
                            caminho, custo = dijkstra_matriz(S, F, adj)
                            if caminho is None:
                                print("⚠️ Sem caminho inicial!")
                                sock.close()
                                return
                            path_str = '[' + ','.join(map(str, caminho)) + ']'
                            resposta = f"PATH={path_str} COST={custo}\n"
                            sock.sendall(resposta.encode('utf-8'))
                            print(f"✅ Enviado (init): {resposta.strip()}")
                    except json.JSONDecodeError:
                        pass
                    continue

                # Comandos de aresta: EDGE_UPDATE, EDGE_ADD, EDGE_REMOVE
                m = re.match(r'UPDATE:\s*(EDGE_UPDATE|EDGE_ADD|EDGE_REMOVE)\s*\((\d+),\s*(\d+),\s*(\d+)\)', linha)
                if m and adj is not None:
                    tipo = m.group(1)
                    u = int(m.group(2))
                    v = int(m.group(3))
                    w = int(m.group(4))
                    # Redimensionar se necessário
                    max_no = max(u, v)
                    if max_no >= len(adj):
                        adj = redimensionar_adj(adj, max_no + 1)
                    if tipo == 'EDGE_UPDATE' or tipo == 'EDGE_ADD':
                        adj[u][v] = w
                        adj[v][u] = w
                        print(f"🔁 {tipo}: ({u},{v}) -> {w}")
                    elif tipo == 'EDGE_REMOVE':
                        adj[u][v] = float('inf')
                        adj[v][u] = float('inf')
                        print(f"🔁 {tipo}: ({u},{v})")
                    # Recalcular
                    caminho, custo = dijkstra_matriz(S, F, adj)
                    if caminho is None:
                        print("⚠️ Sem caminho após comando!")
                        sock.close()
                        return
                    path_str = '[' + ','.join(map(str, caminho)) + ']'
                    resposta = f"PATH={path_str} COST={custo}\n"
                    sock.sendall(resposta.encode('utf-8'))
                    print(f"✅ Enviado (update): {resposta.strip()}")
                    continue

                # OK (k/70) – apenas log
                ok = re.match(r'OK\s*\((\d+)/70\)', linha)
                if ok:
                    print(f"📊 Rodada {ok.group(1)}/70 confirmada")
                    continue

                # Outras linhas (banner, avisos)
                print(f"📄 {linha}")

        except socket.timeout:
            continue
        except Exception as e:
            print(f"Erro: {e}")
            break

    sock.close()

if __name__ == "__main__":
    main()