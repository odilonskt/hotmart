import socket
import json
import re
import time

HOST = "98.94.69.132"
PORT = 32442

# --- Sua função solve_knapsack permanece a mesma ---
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
    best_cap = max(w for w in range(capacity + 1) if dp[n][w] == best_val)
    indices = []
    w = best_cap
    for i in range(n, 0, -1):
        if dp[i][w] != dp[i-1][w]:
            indices.append(i-1)
            w -= weights[i-1]
    indices.reverse()
    binary_vector = [1 if i in indices else 0 for i in range(n)]
    return indices, best_val, sum(weights[i] for i in indices), binary_vector

# --- Funções auxiliares (extract_json, recv_until_json) mantidas ---
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

def test_single_format(format_name, format_answer):
    print(f"\n=== TESTANDO: {format_name} ===")
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((HOST, PORT))

    raw = recv_until_json(sock, timeout=10)
    if not raw:
        print("Sem dados do servidor.")
        sock.close()
        return

    text = raw.decode(errors='ignore')
    data = extract_json(text)
    if not data:
        print("JSON não encontrado.")
        sock.close()
        return

    capacity = data.get("capacity")
    values = data.get("values")
    weights = data.get("weights")
    if None in (capacity, values, weights):
        print("JSON incompleto.")
        sock.close()
        return

    indices, best_val, total_weight, binary_vector = solve_knapsack(capacity, values, weights)

    # Gera a resposta no formato específico
    if format_name == "vetor_binario_espaco":
        answer = " ".join(map(str, binary_vector))
    elif format_name == "vetor_binario_string":
        answer = "".join(map(str, binary_vector))
    elif format_name == "indices_0":
        answer = " ".join(map(str, indices))
    elif format_name == "indices_1":
        answer = " ".join(str(i+1) for i in indices)
    elif format_name == "valor_maximo":
        answer = str(best_val)
    elif format_name == "peso_total":
        answer = str(total_weight)
    elif format_name == "json_indices":
        answer = json.dumps({"answer": indices})
    else:
        answer = ""

    print(f"[ENVIANDO] {answer[:100]}")
    sock.sendall(answer.encode() + b"\n")
    time.sleep(0.5)

    # Recebe a resposta
    sock.settimeout(5)
    resp = b""
    try:
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            resp += chunk
    except socket.timeout:
        pass

    sock.close()

    if resp:
        decoded = resp.decode(errors='ignore')
        print("[RESPOSTA]")
        print(decoded[:500])
        if "flag" in decoded.lower():
            print("🏆 FLAG ENCONTRADA!")
            return True
        if "invalid" in decoded.lower() or "wrong" in decoded.lower():
            print("❌ Formato inválido para este servidor.")
            return False
        else:
            print("⚠️ Resposta inesperada, mas não parece erro de formato.")
            return True
    else:
        print("[!] Sem resposta.")
        return False

if __name__ == "__main__":
    formatos_a_testar = [
        ("vetor_binario_espaco", "Vetor binário separado por espaço (ex: 1 0 1)"),
        ("vetor_binario_string", "Vetor binário como string (ex: 101)"),
        ("indices_0", "Índices 0-based separados por espaço"),
        ("indices_1", "Índices 1-based separados por espaço"),
        ("valor_maximo", "Valor máximo da mochila"),
        ("peso_total", "Peso total da solução"),
        ("json_indices", "JSON com chave 'answer'"),
    ]

    for fmt_key, fmt_desc in formatos_a_testar:
        sucesso = test_single_format(fmt_key, fmt_desc)
        if sucesso:
            print(f"\n✅ Formato que funcionou: {fmt_desc}")
            break
        time.sleep(1)