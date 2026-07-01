import socket
import time
import random
import hashlib
import re

HOST = '98.94.69.132'
# Ajustado: o port correto (32440) do enunciado/servidor
PORT = 32440

# Janela inicial: normalmente suficiente. Se falhar, aumente.
WINDOW_SECONDS = 86400


def recv_until(sock, timeout=2.0) -> str:
    sock.settimeout(timeout)
    data = b''
    while True:
        try:
            chunk = sock.recv(4096)
            if not chunk:
                break
            data += chunk
            # banners/msgs costumam conter ':' ou '>'
            if b':' in data or b'>' in data:
                break
        except socket.timeout:
            break
    return data.decode(errors='ignore')


def extract_hash(banner: str):
    # SHA-512 hexdigest tem 128 chars hex
    m = re.search(r'[0-9a-f]{128}', banner)
    return m.group(0) if m else None


def generate_flag_for_seed(seed, inner_len, prefix, charset):
    random.seed(seed)
    inner = ''.join(random.choice(charset) for _ in range(inner_len))
    return f"{prefix}{{{inner}}}"


def seed_candidates(now_int: int):
    seeds = set()

    # int(time.time())
    for t in range(now_int - WINDOW_SECONDS, now_int + WINDOW_SECONDS + 1):
        seeds.add(t)

    # int(time.time()*1000) em saltos de 1ms (limita para não explodir)
    now_ms = int(time.time() * 1000)
    step_ms = 10  # ajuste se precisar
    for t in range(now_ms - WINDOW_SECONDS * 1000, now_ms + WINDOW_SECONDS * 1000 + 1, step_ms):
        seeds.add(t)

    # floats (caso servidor use float time.time())
    for t in range(now_int - 5, now_int + 6):
        base = float(t)
        for frac in (0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 0.0):
            seeds.add(base + frac)

    return sorted(seeds, key=lambda x: float(x))


def main():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((HOST, PORT))
    banner = recv_until(sock)
    sock.close()

    print('[+] Banner recebido:')
    print(banner)

    target_hash = extract_hash(banner)
    if not target_hash:
        print('[!] Hash SHA-512 (128 hex chars) não encontrado no banner.')
        return

    print(f"[+] Hash alvo: {target_hash}")

    # Prefixo compatível com seu exemplo
    prefix = 'Donotecho'

    # Charset compatível com seu exemplo: letras/dígitos + _ @ !
    charset = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_@!'

    # Tamanhos prováveis (ajuste se souber o fixo)
    inner_lens = [8, 10, 12, 14, 16, 20, 24, 28, 32, 40]

    now_int = int(time.time())
    seeds = seed_candidates(now_int)

    print(f"[+] Testando {len(seeds)} sementes × {len(inner_lens)} tamanhos...")

    tested = 0
    total = len(seeds) * len(inner_lens)

    for seed in seeds:
        for inner_len in inner_lens:
            tested += 1
            if tested % 5000 == 0:
                print(f"    Progresso: {tested}/{total}")

            flag = generate_flag_for_seed(seed, inner_len, prefix, charset)
            h = hashlib.sha512(flag.encode()).hexdigest()

            if h == target_hash:
                print('\n✅ FLAG ENCONTRADA!')
                print('Semente:', seed)
                print('Flag:', flag)
                return

    print('\n[!] Nenhuma flag encontrada na janela/charset/testes atuais.')
    print('Dicas: aumente WINDOW_SECONDS e/ou ajuste inner_lens/charset.')


if __name__ == '__main__':
    main()

