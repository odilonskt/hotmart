import socket
import json
import re
import time

HOST = "98.94.69.132"
PORT = 32442

def solve_knapsack(capacity, values, weights):
    n = len(values)
    dp = [[0] * (capacity + 1) for _ in range(n + 1)]
    for i in range(1, n + 1):
        v = values[i-1]
        w = weights[i-1]
        for cap in range(capacity + 1):
            best = dp[i-1][cap]
            if cap >= w:
                cand = dp[i-1][cap - w] + v
                if cand > best:
                    best = cand
            dp[i][cap] = best

    best_val = max(dp[n])
    best_cap = max([w for w in range(capacity + 1) if dp[n][w] == best_val])
    indices = []
    w = best_cap
    for i in range(n, 0, -1):
        if dp[i][w] != dp[i-1][w]:
            indices.append(i-1)
            w -= weights[i-1]
    indices.reverse()
    return indices, best_val, sum(weights[i] for i in indices)

def extract_json(text):
    m = re.search(r'\{.*\}', text, re.DOTALL)
    if m:
        try:
            return json.loads(m.group())
        except:
            pass
    return None

def recv_until_json(sock, timeout=10):
    sock.settimeout(timeout)
    data = b""
    while True:
        try:
            chunk = sock.recv(4096)
            if not chunk:
                break
            data += chunk
            if extract_json(data.decode(errors='ignore')):
                return data
        except socket.timeout:
            continue
    return data

def send_and_get(sock, payload, timeout=5):
    sock.settimeout(timeout)
    sock.sendall(payload.encode() + b"\n")
    resp = b""
    try:
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            resp += chunk
    except socket.timeout:
        pass
    return resp

def main():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((HOST, PORT))
    print("[+] Conectado.")

    while True:
        raw = recv_until_json(sock, timeout=15)
        if not raw:
            break

        text = raw.decode(errors='ignore')
        data = extract_json(text)
        if data is None:
            print("[!] JSON não encontrado.")
            break

        capacity = data.get("capacity")
        values = data.get("values")
        weights = data.get("weights")
        if capacity is None or values is None or weights is None:
            print("[!] JSON incompleto.")
            break

        print(f"[+] Capacidade: {capacity}, Itens: {len(values)}")

        indices, best_val, total_weight = solve_knapsack(capacity, values, weights)

        # Gera candidatos de resposta
        candidates = []

        # Apenas índices (0-based)
        if indices:
            candidates.append(" ".join(str(i) for i in indices))
            candidates.append(",".join(str(i) for i in indices))
            candidates.append("[" + ",".join(str(i) for i in indices) + "]")
            candidates.append("[" + " ".join(str(i) for i in indices) + "]")
            # 1-based
            candidates.append(" ".join(str(i+1) for i in indices))
            candidates.append(",".join(str(i+1) for i in indices))
            candidates.append("[" + ",".join(str(i+1) for i in indices) + "]")
            candidates.append("[" + " ".join(str(i+1) for i in indices) + "]")
            # Com prefixo: contagem
            candidates.append(str(len(indices)) + " " + " ".join(str(i) for i in indices))
            candidates.append(str(len(indices)) + " " + " ".join(str(i+1) for i in indices))
            candidates.append(str(len(indices)) + "," + ",".join(str(i) for i in indices))
            # Com prefixo: valor total
            candidates.append(str(best_val) + " " + " ".join(str(i) for i in indices))
            candidates.append(str(best_val) + " " + " ".join(str(i+1) for i in indices))
            # Com prefixo: peso total
            candidates.append(str(total_weight) + " " + " ".join(str(i) for i in indices))
            candidates.append(str(total_weight) + " " + " ".join(str(i+1) for i in indices))
            # Apenas valor total ou peso total (sem índices)
            candidates.append(str(best_val))
            candidates.append(str(total_weight))
        else:
            candidates.append("0")
            candidates.append("[]")
            candidates.append("")

        # Remove duplicatas
        seen = set()
        unique = []
        for c in candidates:
            if c not in seen:
                seen.add(c)
                unique.append(c)

        success = False
        for ans in unique:
            if ans == "":
                ans = "0"
            print(f"[ENVIANDO] {ans[:100]}{'...' if len(ans)>100 else ''}")
            resp = send_and_get(sock, ans, timeout=5)
            if resp:
                low = resp.lower()
                print("[RESPOSTA]")
                print(resp.decode(errors='ignore')[:200])
                if b"flag" in low:
                    print("🏆 FLAG ENCONTRADA!")
                    sock.close()
                    return
                if b"invalid" in low or b"wrong" in low or b"format" in low or b"answer" in low:
                    continue  # formato inválido, tenta próximo
                # Se não foi inválido, provavelmente aceitou
                success = True
                break
            else:
                print("[!] Sem resposta, tentando próximo...")
                continue

        if not success:
            print("[!] Todos os formatos falharam. Encerrando.")
            break

    sock.close()

if __name__ == "__main__":
    main()