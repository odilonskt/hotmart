from pwn import *
import re
import heapq
from collections import Counter

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
    while len(heap) > 1:
        left = heapq.heappop(heap)
        right = heapq.heappop(heap)
        merged = Node(freq=left.freq+right.freq, left=left, right=right)
        heapq.heappush(heap, merged)
    return heap[0]

def decode_with_tree(encoded, root):
    result = []
    node = root
    for bit in encoded:
        if bit == '0':
            node = node.left
        else:
            node = node.right
        if node.char is not None:
            result.append(node.char)
            node = root
    return ''.join(result)

def decode_with_codes(encoded, codebook):
    decode_map = {v: k for k, v in codebook.items()}
    i = 0
    res = []
    max_len = max(len(c) for c in decode_map)
    while i < len(encoded):
        for l in range(1, max_len+1):
            if encoded[i:i+l] in decode_map:
                res.append(decode_map[encoded[i:i+l]])
                i += l
                break
        else:
            raise ValueError("Código inválido")
    return ''.join(res)

def parse_tree_string(s):
    # Exemplo: "((A B) (C D))" -> constrói árvore
    # Esta é uma implementação simples para árvores com caracteres únicos
    # e sem espaços extras.
    s = s.replace(' ', '')
    # Vamos usar uma pilha
    stack = []
    i = 0
    while i < len(s):
        if s[i] == '(':
            stack.append('(')
            i += 1
        elif s[i] == ')':
            # Fechar nó: pegar os dois últimos elementos da pilha (que são nós ou caracteres)
            right = stack.pop()
            left = stack.pop()
            # O '(' que estava antes deve ser removido
            if stack and stack[-1] == '(':
                stack.pop()  # remove o '(' correspondente
            # Cria nó interno
            merged = Node(left=left, right=right)
            stack.append(merged)
            i += 1
        else:
            # caractere (assumimos que é uma letra)
            char = s[i]
            stack.append(Node(char=char))
            i += 1
    return stack[0] if stack else None

def main():
    conn = remote('98.94.69.132', 32441)
    # Lê linha por linha até encontrar um prompt (ex: "Digite" ou ": ")
    data = b''
    while True:
        try:
            line = conn.recvline(timeout=2.0)
            if not line:
                break
            data += line
            # Se a linha contiver "Digite", ":" ou ">", e já tivermos algo, pode ser o prompt
            if b'Digite' in line or b':' in line or b'>' in line:
                # Dá um tempinho para ver se vem mais dados (opcional)
                # Mas geralmente o prompt é o último
                break
        except Exception:
            break
    data = data.decode()
    print("[+] Dados recebidos:")
    print(data)

    # Este servidor parece enviar apenas uma string (não aparece binário/árvore no log).
    # Então, por enquanto, tentamos respostas na mesma string.
    m = re.search(r'\[Round\s*1\][^\n]*String:\s*([^\n\r]+)', data)
    if not m:
        m = re.search(r'String:\s*([^\n\r]+)', data)
    if not m:
        print("[!] Não encontrei 'String:' no output.")
        conn.close()
        return
    s = m.group(1).strip()
    print("[+] Enviando resposta igual à string recebida:", s)
    conn.sendline(s.encode())

    try:
        response = conn.recvall(timeout=3)
        print("[+] Resposta do servidor:")
        print(response.decode(errors='ignore'))
    except:
        print("[!] Não foi possível ler a resposta final.")
    conn.close()


if __name__ == '__main__':
    main()