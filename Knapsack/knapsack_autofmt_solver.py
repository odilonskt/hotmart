import socket
import json
import re
import time

HOST = "98.94.69.132"
PORT = 32442


def extract_json(text: str):
    m = re.search(r"\{.*\}", text, re.DOTALL)
    if not m:
        return None
    try:
        return json.loads(m.group())
    except Exception:
        return None


def solve_knapsack_01_dp2d(capacity, values, weights, tie_break="max_weight"):
    """Resolve 0/1 knapsack e reconstrói índices.

    tie_break:
      - "max_weight": entre valores máximos, escolhe o subconjunto com MAIOR peso total.
      - "min_weight": entre valores máximos, escolhe o subconjunto com MENOR peso total.

    A validação do servidor costuma ser sensível a desempate, então tentamos os dois.
    """
    n = len(values)

    # dp[i][w] = melhor valor usando primeiros i itens com capacidade w (<= w).
    dp = [[0] * (capacity + 1) for _ in range(n + 1)]

    for i in range(1, n + 1):
        v = values[i - 1]
        wt = weights[i - 1]
        for w in range(capacity + 1):
            best = dp[i - 1][w]  # não pegar
            if w >= wt:
                cand = dp[i - 1][w - wt] + v  # pegar
                if cand > best:
                    best = cand
            dp[i][w] = best

    best_val = max(dp[n])

    # Escolhe best_w com desempate (para reconstrução coerente)
    candidates_w = [w for w in range(capacity + 1) if dp[n][w] == best_val]
    if not candidates_w:
        return []

    if tie_break == "min_weight":
        best_w = min(candidates_w)
    else:
        best_w = max(candidates_w)

    # Reconstrução: decide inclusão comparando dp[i][w] vs dp[i-1][w]
    indices = []
    w = best_w
    for i in range(n, 0, -1):
        if dp[i][w] != dp[i - 1][w]:
            indices.append(i - 1)
            w -= weights[i - 1]

    indices.reverse()
    return indices


def format_answer(indices, index_base=0):
    # Pelo probe: "0 1" e "0,1" são aceitos; priorizamos vírgula sem espaços.
    if not indices:
        return "0"
    idx = sorted([i + index_base for i in indices])
    return ",".join(map(str, idx))


def recv_until_json(sock, timeout_total=10.0):
    start = time.time()
    sock.settimeout(0.5)
    buf = bytearray()
    while True:
        if time.time() - start > timeout_total:
            return None
        try:
            chunk = sock.recv(4096)
            if not chunk:
                return None
            buf += chunk
            data = extract_json(buf.decode(errors="ignore"))
            if data is not None:
                return data
        except socket.timeout:
            continue


def recv_until_marker(sock, markers, timeout_total=5.0):
    start = time.time()
    sock.settimeout(0.5)
    buf = bytearray()
    low_markers = [m.lower() for m in markers]
    while True:
        if time.time() - start > timeout_total:
            return bytes(buf)
        try:
            chunk = sock.recv(4096)
            if not chunk:
                return bytes(buf)
            buf += chunk
            low = buf.decode(errors="ignore").lower()
            for m in low_markers:
                if m in low:
                    return bytes(buf)
        except socket.timeout:
            continue


def main():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((HOST, PORT))

    # banner inicial
    try:
        banner = sock.recv(4096)
        if banner:
            print(banner.decode(errors="ignore"))
    except Exception:
        pass

    while True:
        data = recv_until_json(sock, timeout_total=15.0)
        if data is None:
            break

        capacity = data.get("capacity")
        values = data.get("values")
        weights = data.get("weights")
        if capacity is None or values is None or weights is None:
            continue

        # Tenta reconstrução com dois desempates + dois index bases.
        tie_breaks = ["max_weight", "min_weight"]
        index_bases = [0, 1]

        markers = [
            "flag",
            "invalid response format",
            "wrong answer",
            "invalid",
            "wrong",
            "format",
        ]

        sent_ok = False
        for tb in tie_breaks:
            for ib in index_bases:
                indices = solve_knapsack_01_dp2d(capacity, values, weights, tie_break=tb)
                ans = format_answer(indices, index_base=ib)

                print(f"[ENVIANDO] tie={tb} base={ib} ans={ans!r}")
                sock.sendall(ans.encode() + b"\n")

                resp = recv_until_marker(sock, markers, timeout_total=5.0)
                if not resp:
                    # sem resposta: assume problema de sync e tenta próxima configuração
                    continue

                low = resp.lower()
                print("[RESPOSTA]")
                print(resp.decode(errors="ignore"))

                if b"flag" in low:
                    return

                # Se for erro de formato, tenta outro base/tie.
                if (
                    b"invalid" in low
                    or b"wrong" in low
                    or b"format" in low
                ):
                    # tenta outra configuração
                    continue

                # Se não parece erro óbvio, assume próxima rodada e volta ao loop.
                sent_ok = True
                break

            if sent_ok:
                break

        if not sent_ok:
            # se nada funcionou, segue tentando ainda assim.
            continue

    sock.close()


if __name__ == "__main__":
    main()

