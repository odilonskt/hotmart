import struct, os

wav_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'CTF', 'Nada Soa por Acaso', 'output.wav')
if not os.path.exists(wav_path):
    # Try relative
    wav_path = r'c:\Users\User\Desktop\hotmart\CTF\Nada Soa por Acaso\output.wav'

b = open(wav_path, 'rb').read()
print(f'Total file size: {len(b)} bytes')
print(f'RIFF: {b[:4]}  size: {struct.unpack("<I", b[4:8])[0]}')
print(f'WAVE: {b[8:12]}')
print()

o = 12
while o < len(b) - 7:
    k = b[o:o+4]
    n = struct.unpack('<I', b[o+4:o+8])[0]
    print(f'  offset={o}: chunk={k} size={n} (data @ {o+8}..{o+8+n})')
    preview = b[o+8:o+8+min(n,64)]
    print(f'    preview: {preview[:32].hex()}')
    if k == b'hint':
        print(f'    hint text: {b[o+8:o+8+n]}')
    o = o + 8 + n
    if n % 2 == 1:
        if o < len(b):
            print(f'    (padding byte at {o}: 0x{b[o]:02x})')
        o += 1

print(f'Final offset: {o}, file len: {len(b)}')
