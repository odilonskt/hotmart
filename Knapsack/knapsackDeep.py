import socket
import re
import bisect
import sys

# Mude para 0 se o servidor esperar índices 0-based, ou 1 se esperar 1-based
INDEX_BASE = 1

def subset_sum_mitm(nums, target):
    n = len(nums)
    if n == 0:
        return []

    left = n // 2
    right = n - left

    # Dicionário: soma -> máscara de bits dos itens escolhidos
    L = {0: 0}
    for i in range(left):
        x = nums[i]
        for s, mask in list(L.items()):
            ns = s + x
            if ns not in L:
                L[ns] = mask | (1 << i)

    R = {0: 0}
    for i in range(right):
        x = nums[left + i]
        for s, mask in list(R.items()):
            ns = s + x
            if ns not in R:
                R[ns] = mask | (1 << i)

    R_sums = sorted(R.keys())

    for sL, mL in L.items():
        need = target - sL
        idx = bisect.bisect_left(R_sums, need)
        if idx < len(R_sums) and R_sums[idx] == need:
            mR = R[need]
            mask = mL | (mR << left)
            return [i for i in range(n) if (mask >> i) & 1]

    return None

def parse_challenge(text):
    items = []

    # Tenta achar a lista no formato [1, 2, 3]
    list_match = re.search(r'\[([^\]]+)\]', text)
    if list_match:
        items = [int(x.strip()) for x in list_match.group(1).split(',') if x.strip()]

    # Tenta achar o alvo/soma/capacidade
    target = None
    target_match = re.search(r'(?:[Tt]arget|[Ss]oma|[Aa]lvo|[Cc]apacidade)\s*[=:]\s*(-?\d+)', text)
    if target_match:
        target = int(target_match.group(1))

    if target is None:
        all_ints = list(map(int, re.findall(r'-?\d+', text)))
        if not all_ints:
            return None, None
        target = all_ints[-1]

    if not items:
        all_ints = list(map(int, re.findall(r'-?\d+', text)))
        if len(all_ints) > 1:
            items = all_ints[:-1]
            target = all_ints[-1]
        else:
            return None, None

    return items, target

def main():
    host = "98.94.69.132"
    port = 32442

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((host, port))
    s.settimeout(2)

    data = b""

    while True:
        # Lê os dados do servidor
        data = b""
        while True:
            try:
                chunk = s.recv(4096)
                if not chunk:
                    break
                data += chunk
            except socket.timeout:
                break

        if not data:
            break

        text = data.decode(errors="ignore")
        print("[RECV]")
        print(text)

        items, target = parse_challenge(text)
        if items is None:
            print("Erro ao parsear.")
            break

        print(f"Itens: {items}")
        print(f"Alvo: {target}")

        sol = subset_sum_mitm(items, target)
        if sol is None:
            print("Nenhuma solução encontrada.")
            break

        sol = sorted(sol)

        # Envia os índices
        answer = " ".join(str(i + INDEX_BASE) for i in sol)
        print(f"[ENVIANDO] {answer}")
        s.send(answer.encode() + b"\n")

        # Lê a resposta (pode ser a flag ou próximo desafio)
        s.settimeout(2)
        response = b""
        while True:
            try:
                chunk = s.recv(4096)
                if not chunk:
                    break
                response += chunk
            except socket.timeout:
                break

        print("[RESPOSTA]")
        print(response.decode(errors="ignore"))

        if b"flag" in response.lower() or b"FLAG" in response:
            break

        # Se o servidor continuar enviando novos desafios, o loop repete
        # com os dados da resposta já guardados no data
        data = response

    s.close()

if __name__ == "__main__":
    main()