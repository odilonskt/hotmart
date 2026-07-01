from pwn import remote
import re
import hashlib
import time
import random
import argparse

HOST = '98.94.69.132'
PORT = 32440


def recv_all(sock, timeout=2.0):
    # Recebe até não haver mais dados (com limite de tempo)
    sock.recvtimeout = timeout
    data = b''
    while True:
        try:
            chunk = sock.recv(4096, timeout=timeout)
            if not chunk:
                break
            data += chunk
        except Exception:
            break
    return data


def extract_sha512_hex(text: str):
    # Procura os primeiros 128 caracteres hex consecutivos (sem depender de \b)
    m = re.search(r'([0-9a-fA-F]{128})', text)
    return m.group(1).lower() if m else None


def generate_candidate(seed, method):
    # Gera um “candidate” (bytes/str) e deixa o caller hashificar com SHA-512.
    # Métodos alinhados com os scripts solve_* do repo.
    if isinstance(seed, float):
        seed_int = int(seed)
    else:
        seed_int = seed

    random.seed(seed)

    if method == 'random_int':
        return bytes([random.randint(0, 255) for _ in range(64)])
    if method == 'random_bytes':
        return random.randbytes(64)
    if method == 'getrandbits_little':
        return random.getrandbits(512).to_bytes(64, 'little')
    if method == 'getrandbits_big':
        return random.getrandbits(512).to_bytes(64, 'big')

    if method == 'sha512_seed_digest':
        return hashlib.sha512(str(seed).encode()).digest()
    if method == 'sha512_seed_hexdigest':
        return hashlib.sha512(str(seed).encode()).hexdigest().encode()

    # Tentativas de strings/flags (se o challenge fizer hash do texto final)
    inner_hex16 = ''.join(random.choice('0123456789abcdef') for _ in range(16))
    inner_hex32 = ''.join(random.choice('0123456789abcdef') for _ in range(32))
    chars_alnum = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'
    inner_alnum16 = ''.join(random.choice(chars_alnum) for _ in range(16))
    inner_alnum32 = ''.join(random.choice(chars_alnum) for _ in range(32))

    if method == 'donotctf_hex16':
        return f"donotctf{{{inner_hex16}}}".encode()
    if method == 'donotctf_hex32':
        return f"donotctf{{{inner_hex32}}}".encode()
    if method == 'donotctf_alnum16':
        return f"donotctf{{{inner_alnum16}}}".encode()
    if method == 'donotctf_alnum32':
        return f"donotctf{{{inner_alnum32}}}".encode()

    if method == 'uuid_like':
        # não importa a estrutura; o hash vai decidir
        # (mantido simples pra não depender de uuid)
        return ''.join(random.choice('0123456789abcdef') for _ in range(32)).encode()

    # Fallback: bytes da seed
    if method == 'seed_decimal':
        return str(seed).encode()
    if method == 'seed_hex':
        return hex(seed_int).encode()
    if method == 'seed_bytes_little':
        return seed_int.to_bytes(8, 'little')
    if method == 'seed_bytes_big':
        return seed_int.to_bytes(8, 'big')

    return None


def brute_force_seed(target_hash, window, methods, step_seconds):
    now = int(time.time())

    # Seeds: segundos inteiros + floats equivalentes + variações pequenas
    seeds = set()
    for t in range(now - window, now + window + 1):
        seeds.add(t)
        seeds.add(t / 1.0)
        seeds.add(t * 1000)
        # variações microssegundos
        for frac in (0.1, 0.01, 0.001, 0.0001):
            seeds.add(t + frac)
            seeds.add(t - frac)

    total = len(seeds) * len(methods)
    print(f"[+] Brute force: {len(seeds)} seeds × {len(methods)} métodos = {total} tentativas")

    count = 0
    for method in methods:
        for seed in seeds:
            count += 1
            if count % 50000 == 0:
                print(f"    Progress: {count}/{total}")
            cand = generate_candidate(seed, method)
            if cand is None:
                continue
            if isinstance(cand, str):
                cand = cand.encode()
            h = hashlib.sha512(cand).hexdigest()
            if h == target_hash:
                return seed, method, cand

    return None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--window', type=int, default=1200, help='Janela (segundos) para brute force da seed')
    ap.add_argument('--methods', type=str, default='', help='Lista de métodos separados por vírgula (opcional)')
    args = ap.parse_args()

    methods_default = [
        'random_int', 'random_bytes',
        'getrandbits_little', 'getrandbits_big',
        'sha512_seed_digest', 'sha512_seed_hexdigest',
        'donotctf_hex16', 'donotctf_hex32',
        'donotctf_alnum16', 'donotctf_alnum32',
        'seed_decimal', 'seed_hex',
        'seed_bytes_little', 'seed_bytes_big',
    ]

    methods = [m.strip() for m in args.methods.split(',') if m.strip()] if args.methods else methods_default

    conn = remote(HOST, PORT)

    banner = conn.recvline(timeout=2.0)
    rest = recv_all(conn)
    conn.close()

    banner_full = (banner + rest).decode(errors='ignore')

    print('[+] Banner/Output recebido:')
    print(banner_full)

    target = extract_sha512_hex(banner_full)
    if not target:
        print('[!] Não encontrei um SHA-512 hex (128 chars) no output.');
        return

    print(f"[+] Hash alvo detectado: {target}")

    res = brute_force_seed(target, window=args.window, methods=methods, step_seconds=1)
    if not res:
        print('[!] Nada encontrado com a janela atual. Tente aumentar --window (ex: 86400) e/ou ajustar --methods.')
        return

    seed, method, cand = res
    print('\n✅ FLAG/CANDIDATE ENCONTRADO!')
    print(f"Semente: {seed}")
    print(f"Método: {method}")

    # Tenta imprimir como texto
    try:
        print('Candidate (ASCII/UTF-8):', cand.decode('utf-8'))
    except Exception:
        print('Candidate (hex):', cand.hex())

    # Se o challenge exigir enviar algo de volta, esse script não envia automaticamente.
    # Ele só encontra o candidate que bate com o hash do banner.


if __name__ == '__main__':
    main()

