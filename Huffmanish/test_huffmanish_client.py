from pwn import remote
import re
import heapq
from collections import Counter

HOST = '98.94.69.132'
PORT = 32441

class Node:
    __slots__ = ("char", "freq", "left", "right")
    def __init__(self, char=None, freq=0, left=None, right=None):
        self.char = char
        self.freq = freq
        self.left = left
        self.right = right

    def __lt__(self, other):
        return self.freq < other.freq


def build_tree(freq_dict):
    heap = [Node(ch, f) for ch, f in freq_dict.items()]
    heapq.heapify(heap)

    if not heap:
        return None

    # Huffman: combine two smallest repeatedly
    while len(heap) > 1:
        a = heapq.heappop(heap)
        b = heapq.heappop(heap)
        merged = Node(freq=a.freq + b.freq, left=a, right=b)
        heapq.heappush(heap, merged)

    return heap[0]


def generate_codes(node, prefix="", codebook=None):
    if codebook is None:
        codebook = {}
    if node is None:
        return codebook

    if node.char is not None:
        # single-symbol edge case: ensure non-empty code
        codebook[node.char] = prefix if prefix else "0"
        return codebook

    if node.left is not None:
        generate_codes(node.left, prefix + "0", codebook)
    if node.right is not None:
        generate_codes(node.right, prefix + "1", codebook)
    return codebook


def encode_string(s, codebook):
    return "".join(codebook[ch] for ch in s)


def main():
    conn = remote(HOST, PORT)

    buf = b""
    last_string = None

    while True:
        chunk = conn.recv(timeout=4096)
        if not chunk:
            break
        buf += chunk
        text = buf.decode(errors="ignore")

        # Capture current round string
        m = re.search(r"\bString:\s*([a-zA-Z0-9]+)", text)
        if m:
            last_string = m.group(1).strip()

        # When server asks for response, compute Huffman and send encoded bits
        if "Resposta:" in text:
            if last_string is None:
                raise RuntimeError("Não encontrei 'String:' antes de 'Resposta:'")

            s = last_string
            freq = Counter(s)
            root = build_tree(freq)
            codes = generate_codes(root)
            encoded = encode_string(s, codes)

            print(f"[+] String: {s}")
            print(f"[+] Codificação (bits): {encoded}")

            conn.sendline(encoded.encode())
            buf = b""  # reset buffer after sending

        # Stop if flag appears
        if "flag" in text.lower():
            print(text)
            break

        # Basic termination if server says incorrect
        if "incorre" in text.lower() or "tente" in text.lower():
            # keep reading; don't break
            pass

    conn.close()


if __name__ == "__main__":
    main()

