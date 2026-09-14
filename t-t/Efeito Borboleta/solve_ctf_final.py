import re
import socket
import sys
from typing import List

HOST = "98.94.69.132"
PORT = 32446


def ler_tudo(sock: socket.socket, timeout: float = 2.0) -> str:
    sock.settimeout(timeout)
    dados = b""
    while True:
        try:
            chunk = sock.recv(4096)
            if not chunk:
                break
            dados += chunk
        except socket.timeout:
            break
    return dados.decode(errors="ignore")


def recv_until(sock: socket.socket, marker: bytes, timeout: float = 10.0) -> bytes:
    sock.settimeout(timeout)
    buf = b""
    while marker not in buf:
        chunk = sock.recv(4096)
        if not chunk:
            break
        buf += chunk
    return buf


def parse_s_expression_numbers(tree_s: str) -> List[str]:
    """Extrai valores numéricos em ordem in-order a partir de uma S-expression binária."""
    tokens = re.findall(r"\(|\)|-?\d+", tree_s)
    idx = 0

    def parse() -> List[str]:
        nonlocal idx
        if idx >= len(tokens):
            return []
        if tokens[idx] != "(":
            idx += 1
            return []

        idx += 1  # consume '('

        # folha vazia: '()'
        if idx < len(tokens) and tokens[idx] == ')':
            idx += 1
            return []

        root = tokens[idx]
        idx += 1

        left = parse()
        right = parse()

        if idx < len(tokens) and tokens[idx] == ')':
            idx += 1

        return left + [root] + right

    return parse()


def recv_line(sock: socket.socket, timeout: float = 10.0, max_bytes: int = 10_000_000) -> str:
    """Lê até encontrar '\n' (ou EOF/timeout). Retorna string sem '\n' no final."""
    sock.settimeout(timeout)
    buf = bytearray()
    while True:
        if len(buf) > max_bytes:
            break
        chunk = sock.recv(4096)
        if not chunk:
            break
        buf.extend(chunk)
        if b"\n" in chunk:
            break
    return bytes(buf).decode(errors="ignore").strip()


def main() -> None:
    r = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    r.connect((HOST, PORT))

    # banner + instruções (fase 1)
    recv_until(r, b"Faca o percurso in-order", timeout=20)
    data = ler_tudo(r, timeout=2.0)

    # extrai primeira S-expression possível (tudo após o primeiro '(')
    if "(" in data:
        tree_s = data[data.find("(") :]
    else:
        tree_s = data

    inorder_values = parse_s_expression_numbers(tree_s)
    if not inorder_values:
        raise RuntimeError("Falha ao extrair S-expression (in-order vazio).")

    # envia fase 1
    r.sendall((",".join(inorder_values) + "\n").encode())

    # fase 2
    recv_until(r, b"Envie o array de ranks", timeout=20)

    vals_int = [int(v) for v in inorder_values]
    unicos = sorted(set(vals_int))

    rank_map = {v: i for i, v in enumerate(unicos)}
    rank_to_value = {i: v for i, v in enumerate(unicos)}
    array_ranks = [rank_map[v] for v in vals_int]

    r.sendall((",".join(map(str, array_ranks)) + "\n").encode())

    # fase 3
    versions = {0: array_ranks.copy()}
    next_version = 1

    while True:
        line = recv_line(r, timeout=10.0)
        if not line:
            # tenta de novo (servidor pode mandar só espaçamentos)
            continue

        low = line.lower()
        if "flag" in low or "{" in line:
            print(line)
            break

        if line.startswith("U "):
            parts = line.split()
            # esperado: U base_ver idx new_val
            if len(parts) != 4:
                continue

            base_ver = int(parts[1])
            idx = int(parts[2])
            new_val = int(parts[3])

            new_rank = rank_map.get(new_val, 0)

            base_arr = versions[base_ver]
            new_arr = base_arr.copy()
            new_arr[idx] = new_rank
            versions[next_version] = new_arr
            r.sendall((str(next_version) + "\n").encode())
            next_version += 1

        elif line.startswith("Q "):
            parts = line.split()
            # esperado: Q ver l r k
            if len(parts) != 5:
                continue

            ver = int(parts[1])
            l = int(parts[2])
            r_idx = int(parts[3])
            k = int(parts[4])

            arr = versions[ver]
            sub = arr[l : r_idx + 1]
            sub.sort()

            rank_k = sub[k - 1]
            answer_val = rank_to_value[rank_k]
            r.sendall((str(answer_val) + "\n").encode())

        else:
            # ignora linhas que não são comando
            continue

    r.close()


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print(f"[ERRO] {e}")
        sys.exit(1)

