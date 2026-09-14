import sys, struct, functools

R = lambda p: open(p, 'rb').read()

def C_fixed(b):
    """Parser RIFF corrigido"""
    o = 12; d = {}
    while o < len(b) - 8:
        k = b[o:o+4]; n = struct.unpack('<I', b[o+4:o+8])[0]
        d[k] = b[o+8:o+8+n]
        o = o + 8 + n
    return d

# LFSR bugado (original do desafio)
def L_bugado(x):
    f = ((x >> 15) ^ (x >> 13) ^ (x >> 12) ^ (x >> 9)) & 1
    return ((x << 1) | f) & 0xFFFF

# Candidatos a LFSR correto (polinomios maximais de 16 bits)
def L_fix1(x):
    """x^16 + x^14 + x^13 + x^11 + 1  ->  taps 15,13,12,10"""
    f = ((x >> 15) ^ (x >> 13) ^ (x >> 12) ^ (x >> 10)) & 1
    return ((x << 1) | f) & 0xFFFF

def L_fix2(x):
    """x^16 + x^15 + x^13 + x^4 + 1  ->  taps 15,14,12,3"""
    f = ((x >> 15) ^ (x >> 14) ^ (x >> 12) ^ (x >> 3)) & 1
    return ((x << 1) | f) & 0xFFFF

def L_fix3(x):
    """x^16 + x^12 + x^3 + x + 1  ->  taps 15,11,2,0"""
    f = ((x >> 15) ^ (x >> 11) ^ (x >> 2) ^ x) & 1
    return ((x << 1) | f) & 0xFFFF

def L_fix4(x):
    """x^16 + x^5 + x^3 + x^2 + 1  ->  taps 15,4,2,1"""
    f = ((x >> 15) ^ (x >> 4) ^ (x >> 2) ^ (x >> 1)) & 1
    return ((x << 1) | f) & 0xFFFF

def L_fix5(x):
    """x^16 + x^15 + x^13 + x^11 + 1  (swap of 9->11)"""
    f = ((x >> 15) ^ (x >> 13) ^ (x >> 12) ^ (x >> 11)) & 1
    return ((x << 1) | f) & 0xFFFF

def L_fix6(x):
    """Taps: 15, 13, 12, 8  (off by one from 9 on the other side)"""
    f = ((x >> 15) ^ (x >> 13) ^ (x >> 12) ^ (x >> 8)) & 1
    return ((x << 1) | f) & 0xFFFF

def I_gen(s, n, m, lfsr_fn):
    u = set(); r = []; v = s
    for _ in range(n):
        v = lfsr_fn(v); j = v % m
        while j in u:
            v = lfsr_fn(v); j = v % m
        u.add(j); r.append(j)
    return r

G = lambda w: [(w[2*i] | (w[2*i+1] << 8)) for i in range(len(w) // 2)]
E = lambda v: v - 0x10000 if v >= 0x8000 else v
X = lambda v: v & 1

def H(c):
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

def try_decode(smp, lfsr_fn, label):
    """Tenta decodificar com uma variante de LFSR"""
    idx = I_gen(0xBEEF, 16, len(smp), lfsr_fn)
    hb = [X(smp[i]) for i in idx]
    n = bits2byte(hb)
    
    ok = 0 < n < 5000 and n * 7 + 16 < len(smp)
    status = "OK" if ok else "INVALIDO"
    print(f"  [{label}] n={n} ({status})")
    
    if not ok:
        return None
    
    idx2 = I_gen(0xBEEF, 16 + n * 7, len(smp), lfsr_fn)[16:]
    pb = [X(smp[i]) for i in idx2]
    
    blocks = [pb[i:i+7] for i in range(0, len(pb), 7)]
    nb = [H(c) for c in blocks]
    fb = [bit for q in nb for bit in q]
    
    by = bytes(bits2byte(fb[i:i+8]) for i in range(0, len(fb), 8))
    return by

if __name__ == '__main__':
    wav = sys.argv[1] if len(sys.argv) > 1 else 'output.wav'
    b = R(wav)
    d = C_fixed(b)
    
    print(f"Chunks: {[k for k in d.keys()]}")
    hint = d.get(b'hint')
    if hint:
        print(f"Hint: {hint}")
    print()
    
    dt = d[b'data']
    smp = [E(v) for v in G(dt)]
    print(f"Samples: {len(smp)}")
    print()
    
    candidates = [
        (L_bugado, "original (bugado, taps 15,13,12,9)"),
        (L_fix1, "fix1 (taps 15,13,12,10)"),
        (L_fix2, "fix2 (taps 15,14,12,3)"),
        (L_fix3, "fix3 (taps 15,11,2,0)"),
        (L_fix4, "fix4 (taps 15,4,2,1)"),
        (L_fix5, "fix5 (taps 15,13,12,11)"),
        (L_fix6, "fix6 (taps 15,13,12,8)"),
    ]
    
    print("=== Testando variantes de LFSR ===")
    for lfsr_fn, label in candidates:
        result = try_decode(smp, lfsr_fn, label)
        if result is not None:
            try:
                text = result.decode('ascii', errors='replace')
                printable = sum(1 for c in text if c.isprintable())
                ratio = printable / len(text) if text else 0
                print(f"    payload ({len(result)} bytes, {ratio:.0%} printable): {text[:200]}")
                if ratio > 0.8:
                    print(f"    >>> PROVAVEL FLAG: {text}")
            except:
                print(f"    payload (raw): {result[:100].hex()}")
    
    # Tambem testar com seeds diferentes
    print()
    print("=== Testando seeds alternativos com LFSR original ===")
    for seed in [0xDEAD, 0xCAFE, 0xFACE, 0x1337, 0xBEEF]:
        idx = I_gen(seed, 16, len(smp), L_bugado)
        hb = [X(smp[i]) for i in idx]
        n = bits2byte(hb)
        ok = 0 < n < 5000
        if ok:
            print(f"  [seed=0x{seed:04X}] n={n} -- VALIDO!")
        else:
            print(f"  [seed=0x{seed:04X}] n={n}")
    
    # Testar com bit extraction diferente (bit 1 em vez de bit 0)
    print()
    print("=== Testando extrair bit 1 em vez de bit 0 ===")
    X2 = lambda v: (v >> 1) & 1
    idx = I_gen(0xBEEF, 16, len(smp), L_bugado)
    hb = [X2(smp[i]) for i in idx]
    n = bits2byte(hb)
    print(f"  [bit1, LFSR bugado] n={n}")
    
    for lfsr_fn, label in candidates[:3]:
        idx = I_gen(0xBEEF, 16, len(smp), lfsr_fn)
        hb = [X2(smp[i]) for i in idx]
        n = bits2byte(hb)
        print(f"  [bit1, {label}] n={n}")
