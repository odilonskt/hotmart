import struct

wav_path = r'c:\Users\User\Desktop\hotmart\CTF\Nada Soa por Acaso\output.wav'
b = open(wav_path, 'rb').read()

print(f'Total file size: {len(b)} bytes')
print(f'RIFF size: {struct.unpack("<I", b[4:8])[0]}')
print()

# Walk chunks with correct parser
o = 12
chunks = {}
while o < len(b) - 7:
    k = b[o:o+4]
    n = struct.unpack('<I', b[o+4:o+8])[0]
    chunks[k] = (o+8, n)
    print(f'  offset={o}: chunk={k} size={n}')
    if k == b'fmt ':
        fmt_data = b[o+8:o+8+n]
        audio_fmt = struct.unpack('<H', fmt_data[0:2])[0]
        channels = struct.unpack('<H', fmt_data[2:4])[0]
        sample_rate = struct.unpack('<I', fmt_data[4:8])[0]
        bits_per_sample = struct.unpack('<H', fmt_data[14:16])[0]
        print(f'    fmt={audio_fmt}, channels={channels}, rate={sample_rate}, bits={bits_per_sample}')
    if k == b'hint':
        hint_data = b[o+8:o+8+n]
        print(f'    hint: {hint_data}')
    o = o + 8 + n

print()

# Now decode
dt_offset, dt_size = chunks[b'data']
dt = b[dt_offset:dt_offset+dt_size]

# Samples
G = lambda w: [(w[2*i] | (w[2*i+1] << 8)) for i in range(len(w) // 2)]
E = lambda v: v - 0x10000 if v >= 0x8000 else v
X = lambda v: v & 1

smp = [E(v) for v in G(dt)]
print(f'Samples: {len(smp)}')

# LFSR
def L(x):
    f = ((x >> 15) ^ (x >> 13) ^ (x >> 12) ^ (x >> 9)) & 1
    return ((x << 1) | f) & 0xFFFF

def I(s, n, m):
    u = set(); r = []; v = s
    for _ in range(n):
        v = L(v); j = v % m
        while j in u:
            v = L(v); j = v % m
        u.add(j); r.append(j)
    return r

import functools
def bits2byte(bits):
    return functools.reduce(lambda a, b: (a << 1) | b, bits, 0)

# Extract first 16 bits (the length)
idx = I(0xBEEF, 16, len(smp))
hb = [X(smp[i]) for i in idx]
n_msb = bits2byte(hb)
print(f'n (MSB-first, 16 bits) = {n_msb}')

# Try LSB-first
n_lsb = bits2byte(reversed(hb))
print(f'n (LSB-first, 16 bits) = {n_lsb}')

# Try just 8 bits
hb8 = [X(smp[i]) for i in idx[:8]]
n8 = bits2byte(hb8)
print(f'n (first 8 bits) = {n8}')

# Show the raw bits
print(f'First 16 LSBs: {hb}')
print(f'Indices: {idx}')

# Show the samples at those indices
print(f'Samples at indices: {[smp[i] for i in idx]}')
print(f'Unsigned at indices: {[G(dt)[i] for i in idx]}')
