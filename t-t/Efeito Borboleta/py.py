from pwn import *
import re

r = remote('98.94.69.132', 32446)

# ========== FASE 1 ==========
r.recvuntil(b"[Fase 1] Arvore binaria (S-expression). Faca o percurso in-order:\n")
tree_string = r.recvline().decode().strip()

def parse_and_inorder(s):
    tokens = re.findall(r'\(|\)|\d+', s)
    idx = 0
    def parse():
        nonlocal idx
        if idx >= len(tokens):
            return []
        tok = tokens[idx]
        if tok == '(':
            idx += 1
            if tokens[idx] == ')':
                idx += 1
                return []
            root_val = tokens[idx]
            idx += 1
            left = parse()
            right = parse()
            if idx < len(tokens) and tokens[idx] == ')':
                idx += 1
            return left + [root_val] + right
        return []
    return parse()

inorder_values = parse_and_inorder(tree_string)
r.sendline(",".join(inorder_values).encode())

# ========== FASE 2 ==========
r.recvuntil(b"Envie o array de ranks (formato: 0,1,2...):")

valores_int = [int(v) for v in inorder_values]
unicos = sorted(set(valores_int))
rank_map = {v: i for i, v in enumerate(unicos)}
rank_to_value = {i: v for i, v in enumerate(unicos)}
array_ranks = [rank_map[v] for v in valores_int]

r.sendline(",".join(str(x) for x in array_ranks).encode())

# ========== FASE 3 ==========
versions = {0: array_ranks.copy()}
next_version = 1

while True:
    try:
        line = r.recvline().decode().strip()
    except EOFError:
        break
    if not line:
        continue

    # Ignora linhas de exemplo/instrução
    if '<' in line or '->' in line:
        continue
    if line.startswith('Dominio') or line.startswith('OK') or line.startswith('Fase'):
        continue

    print("[SERVIDOR]", line)

    if line.startswith('U '):
        parts = line.split()
        if len(parts) != 4:
            print(f"Formato U inesperado: {line}")
            continue
        _, base_ver, idx, new_val = parts
        base_ver = int(base_ver)
        idx = int(idx)
        new_val = int(new_val)

        if new_val not in rank_map:
            # Caso raro: valor não mapeado (não deve ocorrer)
            print(f"Valor {new_val} não encontrado no mapeamento!")
            r.sendline(b'0')
            continue

        new_rank = rank_map[new_val]
        base_arr = versions[base_ver]
        new_arr = base_arr.copy()
        new_arr[idx] = new_rank
        versions[next_version] = new_arr
        r.sendline(str(next_version).encode())
        next_version += 1

    elif line.startswith('Q '):
        parts = line.split()
        if len(parts) != 5:
            print(f"Formato Q inesperado: {line}")
            r.sendline(b'0')
            continue
        _, ver, l, r_idx, k = parts
        ver = int(ver)
        l = int(l)
        r_idx = int(r_idx)
        k = int(k)

        arr = versions[ver]
        sub = arr[l:r_idx+1]
        sub.sort()
        rank_k = sub[k-1]
        r.sendline(str(rank_to_value[rank_k]).encode())

    else:
        # Pode ser a flag
        if 'flag' in line.lower() or '{' in line:
            print("FLAG:", line)
            break
        continue

r.close()