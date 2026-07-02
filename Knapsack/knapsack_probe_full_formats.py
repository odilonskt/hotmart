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
    # Escolhe a capacidade que dá o maior valor (desempate: maior peso)
    best_cap = max([w for w in range(capacity + 1) if dp[n][w] == best_val])

    indices = []
    w = best_cap
    for i in range(n, 0, -1):
        if dp[i][w] != dp[i-1][w]:
            indices.append(i-1)
            w -= weights[i-1]
    indices.reverse()
    return indices, best_val

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
        raw = recv_until_json(sock, timeout=10)
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

        indices, best_val = solve_knapsack(capacity, values, weights)
        total_weight = sum(weights[i] for i in indices)
        total_value = best_val

        # Gera todos os candidatos de formato
        candidates = []

        # Índices separados por espaço (base 0)
        if indices:
            candidates.append(" ".join(str(i) for i in indices))
            candidates.append(" ".join(str(i+1) for i in indices))
            candidates.append(",".join(str(i) for i in indices))
            candidates.append(",".join(str(i+1) for i in indices))
            candidates.append("[" + ",".join(str(i) for i in indices) + "]")
            candidates.append("[" + " ".join(str(i) for i in indices) + "]")
            candidates.append("[" + ",".join(str(i+1) for i in indices) + "]")
            candidates.append("[" + " ".join(str(i+1) for i in indices) + "]")
        else:
            candidates.append("0")
            candidates.append("[]")
            candidates.append("")

        # Apenas valores agregados (alguns servidores aceitam)
        candidates.append(str(total_value))
        candidates.append(str(total_weight))
        candidates.append(str(len(indices)))

        # Remove duplicatas e mantém ordem
        seen = set()
        unique_candidates = []
        for c in candidates:
            if c not in seen:
                seen.add(c)
                unique_candidates.append(c)

        success = False
        for ans in unique_candidates:
            if ans == "":
                ans = "0"  # fallback
            print(f"[ENVIANDO] {ans}")
            resp = send_and_get(sock, ans, timeout=5)
            if resp:
                low = resp.lower()
                print("[RESPOSTA]")
                print(resp.decode(errors='ignore'))
                if b"flag" in low:
                    print("🏆 FLAG ENCONTRADA!")
                    sock.close()
                    return
                if b"invalid" in low or b"wrong" in low or b"format" in low or b"answer" in low:
                    continue  # tenta próximo formato
                # Se não foi erro, provavelmente aceitou
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