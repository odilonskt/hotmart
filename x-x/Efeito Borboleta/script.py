import socket
import sys
import bisect

# ===== CONFIGURAÇÃO =====
HOST = "98.94.69.132"
PORT = 32447
# =========================

sys.setrecursionlimit(200000)

# ==================== NETWORK ====================

buf = b""

def recv_until_keyword(sock, keywords, timeout=8):
    global buf
    sock.settimeout(timeout)
    while True:
        text = buf.decode(errors="replace")
        for kw in keywords:
            if kw in text:
                sock.settimeout(0.3)
                try:
                    while True:
                        d = sock.recv(4096)
                        if not d: break
                        buf += d
                except: pass
                result = buf
                buf = b""
                return result.decode(errors="replace")
        try:
            d = sock.recv(65536)
            if not d: break
            buf += d
        except socket.timeout:
            break
    result = buf
    buf = b""
    return result.decode(errors="replace")


def recv_line(sock, timeout=5):
    global buf
    sock.settimeout(timeout)
    while b"\n" not in buf:
        try:
            d = sock.recv(4096)
            if not d: break
            buf += d
        except socket.timeout:
            break
    if b"\n" in buf:
        line, buf = buf.split(b"\n", 1)
        return line.decode(errors="replace").strip()
    result = buf.decode(errors="replace").strip()
    buf = b""
    return result


def send_answer(sock, msg):
    sock.sendall((msg + "\n").encode())


# ==================== TREE PARSING ====================

def parse_tree_iterative(s):
    pos = 0
    n = len(s)

    def skip_spaces():
        nonlocal pos
        while pos < n and s[pos] == ' ':
            pos += 1

    stack = []
    result = None
    skip_spaces()
    if pos >= n or s[pos] != '(':
        return None
    stack.append([0, None, None, None])

    while stack:
        frame = stack[-1]
        state = frame[0]

        if state == 0:
            skip_spaces()
            if pos >= n or s[pos] != '(':
                stack.pop()
                result = None
                continue
            pos += 1
            skip_spaces()
            if pos < n and s[pos] == ')':
                pos += 1
                stack.pop()
                result = None
                continue
            num_start = pos
            while pos < n and s[pos] not in ' ()':
                pos += 1
            frame[1] = int(s[num_start:pos])
            frame[0] = 1
            skip_spaces()
            stack.append([0, None, None, None])

        elif state == 1:
            frame[2] = result
            frame[0] = 2
            skip_spaces()
            stack.append([0, None, None, None])

        elif state == 2:
            frame[3] = result
            skip_spaces()
            if pos < n and s[pos] == ')':
                pos += 1
            result = (frame[1], frame[2], frame[3])
            stack.pop()

    return result


def in_order(node):
    result = []
    stack = []
    current = node
    while stack or current is not None:
        while current is not None:
            stack.append(current)
            _, left, _ = current
            current = left
        current = stack.pop()
        val, _, right = current
        result.append(val)
        current = right
    return result


def extract_tree_string(data):
    lines = data.split('\n')
    tree_parts = []
    in_tree = False
    for line in lines:
        stripped = line.strip()
        if not in_tree and stripped.startswith('('):
            in_tree = True
        if in_tree:
            if 'Envie' in stripped or 'envie' in stripped:
                idx = stripped.find('Envie')
                if idx > 0:
                    tree_parts.append(stripped[:idx].strip())
                break
            tree_parts.append(stripped)
    return ' '.join(tree_parts)


# ==================== PERSISTENT SEGMENT TREE ====================

class Node:
    __slots__ = ('count', 'left', 'right')
    def __init__(self, count, left=None, right=None):
        self.count = count
        self.left = left
        self.right = right

null_node = Node(0)
null_node.left = null_node
null_node.right = null_node

def build_seg_tree(l, r):
    if l == r:
        return null_node
    mid = (l + r) // 2
    return Node(0, build_seg_tree(l, mid), build_seg_tree(mid + 1, r))

def update_seg_tree(node, l, r, val, diff):
    if l == r:
        return Node(node.count + diff, null_node, null_node)
    mid = (l + r) // 2
    if val <= mid:
        return Node(node.count + diff, update_seg_tree(node.left, l, mid, val, diff), node.right)
    else:
        return Node(node.count + diff, node.left, update_seg_tree(node.right, mid + 1, r, val, diff))

# Query K-th element iterativo com correções dinâmicas pré-filtradas
def query_kth_iterative(node_l, node_r, max_rank, k, filtered_mods):
    l = 0
    r = max_rank
    
    while l < r:
        count_left = node_r.left.count - node_l.left.count
        mid = (l + r) // 2
        
        # Aplica as correções para o nó esquerdo [l, mid]
        for old_rank, new_rank in filtered_mods:
            if l <= old_rank <= mid:
                count_left -= 1
            if l <= new_rank <= mid:
                count_left += 1
                
        if count_left >= k:
            node_l = node_l.left
            node_r = node_r.left
            r = mid
        else:
            node_l = node_l.right
            node_r = node_r.right
            k -= count_left
            l = mid + 1
            
    return l


# ==================== FASE 3 HELPERS ====================

def is_command(line):
    line = line.strip()
    if len(line) < 3:
        return False
    if line[0] in 'UQ' and line[1] == ' ':
        rest = line[2:].split()
        if rest and rest[0].isdigit():
            return True
    return False


# ==================== MAIN ====================

def main():
    global buf
    buf = b""

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(15)

    print(f"[*] Conectando em {HOST}:{PORT}...")
    sock.connect((HOST, PORT))
    print("[+] Conectado!\n")

    try:
        # ===== FASE 1: In-order traversal =====
        print("=" * 60)
        print("[FASE 1] Recebendo arvore...")
        data = recv_until_keyword(sock, ["Envie"])

        tree_str = extract_tree_string(data)
        print(f"  [*] Arvore: {len(tree_str)} chars")
        print(f"  [*] Parseando...")
        tree = parse_tree_iterative(tree_str)

        if tree is None:
            print("  [ERRO] Parse falhou!")
            return

        print(f"  [*] Calculando in-order...")
        in_ord = in_order(tree)
        print(f"  [*] {len(in_ord)} nos")

        answer = ",".join(map(str, in_ord))
        print(f"  [*] Enviando ({len(answer)} chars)...")
        send_answer(sock, answer)
        print(f"  [OK] Fase 1 enviada!")

        # ===== FASE 2: Compressão de coordenadas =====
        print("\n" + "=" * 60)
        print("[FASE 2] Recebendo prompt...")
        data = recv_until_keyword(sock, ["Envie"])

        print(f"  [*] Calculando ranks...")
        sorted_unique = sorted(set(in_ord))
        rev_map = sorted_unique
        
        ranks = [bisect.bisect_left(sorted_unique, v) for v in in_ord]
        max_rank = len(sorted_unique) - 1
        print(f"  [*] {len(ranks)} ranks, max rank: {max_rank}")

        answer = ",".join(map(str, ranks))
        print(f"  [*] Enviando ({len(answer)} chars)...")
        send_answer(sock, answer)
        print(f"  [OK] Fase 2 enviada!")

        # ===== FASE 3: Persistent Segment Tree =====
        print("\n" + "=" * 60)
        print("[FASE 3] Recebendo descricao e comandos...")

        # versions_mods[v] guarda um dicionário {idx: (old_rank, new_rank)}
        versions_mods = [{}]
        versions_arr = [ranks]

        print("  [*] Inicializando Segment Trees persistentes da versao 0...")
        seg_roots = [build_seg_tree(0, max_rank)]
        for val in ranks:
            seg_roots.append(update_seg_tree(seg_roots[-1], 0, max_rank, val, 1))

        state = 0

        # Recebe linhas até encontrar o primeiro comando U/Q
        first_cmd = None
        while True:
            line = recv_line(sock, timeout=8)
            if not line:
                continue
            if is_command(line):
                first_cmd = line
                break
            print(f"  [INFO] {line}")
            
            lower = line.lower()
            if 'flag' in lower or 'parabens' in lower or 'congratulations' in lower:
                print(f"\n{'=' * 60}")
                print(f"[FLAG!] {line}")
                print(f"{'=' * 60}")
                return
            if 'encerrada' in lower or 'tempo' in lower:
                print(f"  [!] {line}")
                return

        if first_cmd is None:
            print("  [ERRO] Nenhum comando encontrado!")
            return

        cmd = first_cmd
        round_num = 0

        while cmd:
            round_num += 1

            if cmd.startswith('U '):
                parts = cmd.split()
                vbase = int(parts[1])
                idx = int(parts[2])
                new_val = int(parts[3])

                new_rank = bisect.bisect_left(sorted_unique, new_val)
                if new_rank > max_rank:
                    new_rank = max_rank

                base_mods = versions_mods[vbase]
                new_mods = dict(base_mods)
                orig_rank = ranks[idx]

                if new_rank != orig_rank:
                    new_mods[idx] = (orig_rank, new_rank)
                else:
                    new_mods.pop(idx, None)

                versions_mods.append(new_mods)

                base_ranks = versions_arr[vbase]
                new_ranks = list(base_ranks)
                new_ranks[idx] = new_rank
                versions_arr.append(new_ranks)

                vid = len(versions_mods) - 1
                state = vid

                send_answer(sock, str(vid))
                print(f"  [CMD {round_num}] U base={vbase} idx={idx} val={new_val} -> v{vid} (mods: {len(new_mods)})")

            elif cmd.startswith('Q '):
                parts = cmd.split()
                t = int(parts[1])

                ver = state % len(versions_mods)
                active_mods_dict = versions_mods[ver]

                answers = []
                pi = 2
                
                # Otimização Crítica: Se não houver modificações ativas, a query é puramente O(log N) direto na Segment Tree 0
                if not active_mods_dict:
                    for _ in range(t):
                        l = int(parts[pi])
                        r = int(parts[pi + 1])
                        k = int(parts[pi + 2])
                        pi += 3

                        # Sem modificações ativas:
                        node_l = seg_roots[l]
                        node_r = seg_roots[r + 1]
                        
                        # Loop inline de query do k-ésimo na segment tree 0 (altamente otimizado)
                        ql = 0
                        qr = max_rank
                        while ql < qr:
                            count_left = node_r.left.count - node_l.left.count
                            mid = (ql + qr) // 2
                            if count_left >= k:
                                node_l = node_l.left
                                node_r = node_r.left
                                qr = mid
                            else:
                                node_l = node_l.right
                                node_r = node_r.right
                                k -= count_left
                                ql = mid + 1
                        
                        answers.append(rev_map[ql])
                else:
                    # Converte modificações em uma lista ordenada por índice para busca binária rápida
                    mods_sorted = sorted(active_mods_dict.items()) # lista de (idx, (old_rank, new_rank))
                    mods_indices = [item[0] for item in mods_sorted]

                    for _ in range(t):
                        l = int(parts[pi])
                        r = int(parts[pi + 1])
                        k = int(parts[pi + 2])
                        pi += 3

                        # Filtra apenas modificações que caem no intervalo [l, r] usando bisect (O(log M))
                        idx_start = bisect.bisect_left(mods_indices, l)
                        idx_end = bisect.bisect_right(mods_indices, r)
                        
                        filtered_mods = [
                            mods_sorted[i][1] for i in range(idx_start, idx_end)
                        ] # lista de (old_rank, new_rank)

                        # Executa busca iterativa otimizada
                        rank_ans = query_kth_iterative(
                            seg_roots[l], seg_roots[r + 1], 
                            max_rank, k, filtered_mods
                        )
                        answers.append(rev_map[rank_ans])

                state = sum(answers)
                ans_str = ",".join(map(str, answers))
                send_answer(sock, ans_str)
                print(f"  [CMD {round_num}] Q t={t} ver={ver} -> {ans_str[:80]}...")

            # Recebe próximo comando
            cmd = None
            attempts = 0
            while attempts < 20:
                line = recv_line(sock, timeout=5)
                if not line:
                    attempts += 1
                    if attempts >= 3:
                        break
                    continue
                
                attempts = 0
                if is_command(line):
                    cmd = line
                    break

                lower = line.lower()
                print(f"  [INFO] {line}")

                if 'flag' in lower or 'parabens' in lower or 'congratulations' in lower:
                    print(f"\n{'=' * 60}")
                    print(f"[FLAG!] {line}")
                    print(f"{'=' * 60}")
                    for _ in range(10):
                        extra = recv_line(sock, timeout=2)
                        if extra:
                            print(f"[FLAG] {extra}")
                        else:
                            break
                    return

                if 'encerrada' in lower or 'tempo' in lower:
                    print(f"  [!] {line}")
                    return

        print(f"\n{'=' * 60}")
        print("[*] Aguardando flag...")
        for _ in range(15):
            line = recv_line(sock, timeout=3)
            if not line:
                break
            print(f"[RESP] {line}")

    except Exception as e:
        import traceback
        print(f"[ERRO] {e}")
        traceback.print_exc()
    finally:
        try:
            sock.close()
        except:
            pass
        print("\n[*] Socket fechado. Finalizado.")


if __name__ == "__main__":
    main()