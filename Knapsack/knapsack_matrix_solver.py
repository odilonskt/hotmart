import socket
import json
import re

HOST = "98.94.69.132"
PORT = 32442


def extract_json(text: str):
    match = re.search(r"\{.*\}", text, re.DOTALL)
    if not match:
        return None
    try:
        return json.loads(match.group())
    except Exception:
        return None


def solve_dp_matrix(capacity, values, weights):
    """Monta a matriz dp de 0/1 knapsack.

    dp[i][w] = melhor valor usando itens [0..i] com capacidade w.

    Retorna:
      dp: lista de listas (n+1) x (capacity+1) usando 0..n
    """
    n = len(values)
    dp = [[0] * (capacity + 1) for _ in range(n + 1)]

    for i in range(1, n + 1):
        v = values[i - 1]
        wgt = weights[i - 1]
        for w in range(capacity + 1):
            # não pega
            best = dp[i - 1][w]
            # pega
            if w >= wgt:
                cand = dp[i - 1][w - wgt] + v
                if cand > best:
                    best = cand
            dp[i][w] = best

    return dp


def format_matrix_as_rows(dp):
    """Serializa dp como linhas: "a b c"."""
    return "\n".join(" ".join(map(str, row)) for row in dp)


def main():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((HOST, PORT))
    s.settimeout(5)

    buf = b""
    while True:
        try:
            chunk = s.recv(4096)
        except socket.timeout:
            continue
        if not chunk:
            break
        buf += chunk

        text = buf.decode(errors="ignore")
        data = extract_json(text)
        if data is None:
            continue

        capacity = data.get("capacity")
        values = data.get("values")
        weights = data.get("weights")
        if capacity is None or values is None or weights is None:
            buf = b""
            continue

        # resolve e envia matriz
        dp = solve_dp_matrix(capacity, values, weights)
        payload = format_matrix_as_rows(dp)

        # envia em uma única vez
        s.sendall(payload.encode() + b"\n")

        # lê resposta
        response = b""
        try:
            response = s.recv(4096)
        except socket.timeout:
            response = b""

        if response:
            print(response.decode(errors="ignore"))
            if b"flag" in response.lower() or b"FLAG" in response:
                return

        buf = b""

    s.close()


if __name__ == "__main__":
    main()

