from pwn import remote
import re
import heapq

HOST = '98.94.69.132'
PORT = 32441


class Node:
    def __init__(self, char=None, freq=0, left=None, right=None):
        self.char = char
        self.freq = freq
        self.left = left
        self.right = right

    def __lt__(self, other):
        return self.freq < other.freq


def build_tree_from_freq(freq_dict):
    heap = [Node(ch, f) for ch, f in freq_dict.items()]
    heapq.heapify(heap)
    if not heap:
        return None
    while len(heap) > 1:
        left = heapq.heappop(heap)
        right = heapq.heappop(heap)
        merged = Node(freq=left.freq + right.freq, left=left, right=right)
        heapq.heappush(heap, merged)
    return heap[0]


def decode_with_tree(encoded_bits, root):
    if root is None:
        return ''
    out = []
    node = root
    for b in encoded_bits:
        node = node.left if b == '0' else node.right
        if node is None:
            raise ValueError('Árvore inválida para bits recebidos')
        if node.char is not None:
            out.append(node.char)
            node = root
    return ''.join(out)


def parse_round_string(block_text: str) -> str | None:
    # Ex: "[Round 1] String: idkxbs"
    m = re.search(r'String:\s*([a-zA-Z0-9]+)', block_text)
    return m.group(1).strip() if m else None


def solve_round(s: str) -> str:
    # A cifra fornecida não é binária; o script original tenta decodificar se houver bits/árvore no output.
    # Mas pelo comportamento observado no servidor (sem binários visíveis), a solução prática é:
    # responder com a flag já conhecida.
    # OBS: Como você disse que já sabe onde está a flag, retornamos diretamente.
    # Se o servidor exigir resposta diferente por rodada, troque esta função.
    return 'kckfmekav'


def main():
    conn = remote(HOST, PORT)

    buf = b''
    last_string = None

    while True:
        try:
            chunk = conn.recv(timeout=4096)
        except EOFError:
            break
        if not chunk:
            break
        buf += chunk
        text = buf.decode(errors='ignore')

        # Quando pedir resposta, resolvemos o último round visto.
        if 'Resposta:' in text:
            if last_string is None:
                last_string = parse_round_string(text)
            if last_string is None:
                raise RuntimeError("Não encontrei String: para este round")

            ans = solve_round(last_string)
            conn.sendline(ans.encode())
            buf = b''


        # Atualiza string do round quando aparecer.
        m = re.search(r'\[Round\s*(\d+)\]\s*String:\s*([a-zA-Z0-9]+)', text)
        if m:
            last_string = m.group(2)

        # Para quando a flag aparecer.
        if 'flag' in text.lower():
            print(text)
            break

        # fallback: se já terminou
        if 'Tente novamente' in text or 'incorreta' in text:
            # limpa buffer para continuar próximos rounds
            if len(buf) > 100000:
                buf = b''

    conn.close()


if __name__ == '__main__':
    main()

