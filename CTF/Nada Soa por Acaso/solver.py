import sys, struct, functools

# ---------------------------------------------------------------------------
# Helpers (iguais ao desafio original)
# ---------------------------------------------------------------------------

R = lambda p: open(p, 'rb').read()

def L(x):
    """LFSR 16-bit com taps em 15,13,12,9"""
    f = ((x >> 15) ^ (x >> 13) ^ (x >> 12) ^ (x >> 9)) & 1
    return ((x << 1) | f) & 0xFFFF

def I(s, n, m):
    """Gera n indices unicos no range [0,m) usando o LFSR"""
    u = set(); r = []; v = s
    for _ in range(n):
        v = L(v); j = v % m
        while j in u:
            v = L(v); j = v % m
        u.add(j); r.append(j)
    return r

G = lambda w: [(w[2*i] | (w[2*i+1] << 8)) for i in range(len(w) // 2)]
E = lambda v: v - 0x10000 if v >= 0x8000 else v
X = lambda v: v & 1

def H(c):
    """Hamming(7,4) decoder - corrige 1 bit de erro"""
    p1, p2, d1, p3, d2, d3, d4 = c
    s1 = p1 ^ d1 ^ d2 ^ d4
    s2 = p2 ^ d1 ^ d3 ^ d4
    s4 = p3 ^ d2 ^ d3 ^ d4
    y = (s1 << 2) | (s2 << 1) | s4
    if y:
        c = list(c); c[y - 1] ^= 1
        p1, p2, d1, p3, d2, d3, d4 = c
    return [d1, d2, d3, d4]

def bits2byte(bits):
    return functools.reduce(lambda a, b: (a << 1) | b, bits, 0)

# ---------------------------------------------------------------------------
# Parser RIFF corrigido
# ---------------------------------------------------------------------------

def C_original(b):
    """Parser ORIGINAL (com bug): nao avanca o header (8 bytes) de cada chunk."""
    o = 12; d = {}
    while o < len(b) - 8:
        k = b[o:o+4]; n = struct.unpack('<I', b[o+4:o+8])[0]
        d[k] = b[o+8:o+8+n]
        o = o + n          # BUG: deveria ser o + 8 + n
    return d

def C_fixed(b):
    """Parser CORRIGIDO: avanca 8 bytes (header) + n bytes (payload) a cada chunk."""
    o = 12; d = {}
    while o < len(b) - 8:
        k = b[o:o+4]; n = struct.unpack('<I', b[o+4:o+8])[0]
        d[k] = b[o+8:o+8+n]
        o = o + 8 + n      # CORRIGIDO
    return d

# ---------------------------------------------------------------------------
# Decode - funciona com qualquer parser passado
# ---------------------------------------------------------------------------

def decode(b, parser):
    d = parser(b)

    print(f"[chunks] {[k for k in d.keys()]}")

    dt = d[b'data']
    smp = [E(v) for v in G(dt)]
    print(f"[samples] {len(smp)} amostras")

    # Primeiros 16 bits = comprimento da mensagem (em bytes)
    idx = I(0xBEEF, 16, len(smp))
    hb = [X(smp[i]) for i in idx]
    n = bits2byte(hb)
    print(f"[n] comprimento extraido = {n} bytes")

    if n <= 0 or n > 10000:
        print("[!] Comprimento invalido - parser provavelmente errado")
        return None

    # n*7 bits de payload Hamming(7,4) => n*4 bits => n/2 bytes ASCII
    idx2 = I(0xBEEF, 16 + n * 7, len(smp))[16:]
    pb = [X(smp[i]) for i in idx2]

    blocks = [pb[i:i+7] for i in range(0, len(pb), 7)]
    nb = [H(c) for c in blocks]
    fb = [bit for q in nb for bit in q]

    by = bytes(bits2byte(fb[i:i+8]) for i in range(0, len(fb), 8))
    return by, d.get(b'hint')

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

if __name__ == '__main__':
    wav = sys.argv[1] if len(sys.argv) > 1 else 'output.wav'
    b = R(wav)

    print("=" * 60)
    print("RIFF header:", b[:4], "| tamanho:", struct.unpack('<I', b[4:8])[0])
    print("WAVE tag:", b[8:12])
    print()

    for label, parser in [("ORIGINAL (bugado)", C_original), ("CORRIGIDO", C_fixed)]:
        print(f"--- Parser {label} ---")
        try:
            result = decode(b, parser)
            if result:
                payload, hint = result
                print(f"[payload raw] {payload}")
                print(f"[decode ascii] {payload.decode('ascii', errors='replace')}")
                if hint:
                    print(f"[hint chunk] {hint}")
        except Exception as e:
            print(f"[ERRO] {e}")
        print()
