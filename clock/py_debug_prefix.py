import socket
import time
import random
import hashlib
import re

HOST = '98.94.69.132'
PORT = 32440
WINDOW = 600  # segundos


def recv_until(sock, timeout=2.0):
    sock.settimeout(timeout)
    data = b''
    while True:
        try:
            chunk = sock.recv(4096)
            if not chunk:
                break
            data += chunk
            if b':' in data or b'>' in data:
                break
        except socket.timeout:
            break
    return data.decode(errors='ignore')


def extract_hash(text):
    m = re.search(r'[0-9a-f]{128}', text)
    return m.group(0) if m else None


def generate_key(seed, method):
    if method == 'random_int':
        random.seed(seed)
        return bytes([random.randint(0, 255) for _ in range(64)])
    if method == 'random_bytes':
        random.seed(seed)
        return random.randbytes(64)
    if method == 'getrandbits_little':
        random.seed(seed)
        return random.getrandbits(512).to_bytes(64, 'little')
    if method == 'getrandbits_big':
        random.seed(seed)
        return random.getrandbits(512).to_bytes(64, 'big')
    if method == 'sha512_seed_trunc':
        return hashlib.sha512(str(seed).encode()).digest()[:64]
    if method == 'sha512_seed_full':
        return hashlib.sha512(str(seed).encode()).digest()
    return None


def prefix_score(hex_digest, target_hex):
    # Quantos hex chars iniciais batem
    n = min(len(hex_digest), len(target_hex))
    i = 0
    while i < n and hex_digest[i] == target_hex[i]:
        i += 1
    return i


def main():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((HOST, PORT))
    banner = recv_until(sock)
    sock.close()

    print("[+] Banner:")
    print(banner)

    target_hash = extract_hash(banner)
    if not target_hash:
        print("[!] Hash não encontrado.")
        return
    print(f"[+] Hash alvo: {target_hash[:32]}...")

    methods = [
        'random_int',
        'random_bytes',
        'getrandbits_little',
        'getrandbits_big',
        'sha512_seed_trunc',
        'sha512_seed_full',
    ]

    now_int = int(time.time())
    seeds = set()

    # 1) int(time.time())
    for t in range(now_int - WINDOW, now_int + WINDOW + 1):
        seeds.add(t)

    # 2) int(time.time()*1000)
    now_ms = int(time.time() * 1000)
    for t in range(now_ms - WINDOW * 1000, now_ms + WINDOW * 1000 + 1, 1_000):
        # passo 1s em ms para manter controlado
        seeds.add(t)

    # 3) float(time.time())
    for t in range(now_int - 5, now_int + 6):
        base = float(t)
        for frac in [0.0, 0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9]:
            seeds.add(base + frac)

    seeds = sorted(seeds, key=lambda x: float(x))
    print(f"[+] Testando {len(seeds)} sementes x {len(methods)} métodos = {len(seeds)*len(methods)} chaves")

    best = {'score': -1, 'method': None, 'seed': None, 'key_hex': None, 'hash_hex': None}

    tested = 0
    total = len(seeds) * len(methods)

    for method in methods:
        for seed in seeds:
            tested += 1
            if tested % 5000 == 0:
                print(f"    Progresso: {tested}/{total} | best_score={best['score']} method={best['method']} seed={best['seed']}")

            key = generate_key(seed, method)
            if key is None:
                continue
            h = hashlib.sha512(key).hexdigest()

            if h == target_hash:
                print("\n✅ FLAG ENCONTRADA (hash bateu exatamente)!")
                print(f"Semente: {seed} (método {method})")
                print("Flag (hex):", key.hex())
                return

            sc = prefix_score(h, target_hash)
            if sc > best['score']:
                best = {
                    'score': sc,
                    'method': method,
                    'seed': seed,
                    'key_hex': key.hex(),
                    'hash_hex': h,
                }

    print("\n[!] Nenhuma correspondência exata encontrada.")
    print(f"    Melhor prefix match: {best['score']} hex chars")
    print(f"    Melhor método: {best['method']}")
    print(f"    Melhor seed: {best['seed']}")
    print(f"    Hash obtido: {best['hash_hex']}")
    print(f"    Hash alvo:   {target_hash}")


if __name__ == "__main__":
    main()

