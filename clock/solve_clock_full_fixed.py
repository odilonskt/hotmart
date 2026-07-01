import socket, time, random, hashlib, re, base64, uuid

HOST = '98.94.69.132'
PORT = 32440
WINDOW = 172800  # 48 horas (aumente se necessário)

def recv_until(sock, timeout=2.0):
    sock.settimeout(timeout)
    data = b''
    while True:
        try:
            chunk = sock.recv(4096)
            if not chunk: break
            data += chunk
            if b':' in data or b'>' in data: break
        except socket.timeout: break
    return data.decode(errors='ignore')

def extract_hash(text):
    m = re.search(r'[0-9a-f]{128}', text)
    return m.group(0) if m else None

def generate_flag(seed, method):
    # Converte seed para int se for float (para métodos que exigem int)
    if isinstance(seed, float):
        seed_int = int(seed)
    else:
        seed_int = seed

    random.seed(seed)
    if method == 'random_int':
        return bytes([random.randint(0,255) for _ in range(64)])
    elif method == 'random_bytes':
        return random.randbytes(64)
    elif method == 'getrandbits_little':
        return random.getrandbits(512).to_bytes(64, 'little')
    elif method == 'getrandbits_big':
        return random.getrandbits(512).to_bytes(64, 'big')
    elif method == 'sha512_seed':
        return hashlib.sha512(str(seed).encode()).digest()
    elif method == 'sha512_seed_hex':
        return hashlib.sha512(str(seed).encode()).hexdigest().encode()
    # Métodos que usam seed_int (para hex/bytes)
    elif method == 'seed_hex':
        return hex(seed_int).encode()
    elif method == 'seed_bytes_little':
        return seed_int.to_bytes(8, 'little')
    elif method == 'seed_bytes_big':
        return seed_int.to_bytes(8, 'big')
    # Formatos de flag com prefixo 'flag{...}' e 'donotctf{...}'
    elif method == 'flag_hex16':
        inner = ''.join(random.choice('0123456789abcdef') for _ in range(16))
        return f"flag{{{inner}}}".encode()
    elif method == 'flag_hex32':
        inner = ''.join(random.choice('0123456789abcdef') for _ in range(32))
        return f"flag{{{inner}}}".encode()
    elif method == 'flag_alnum16':
        chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'
        inner = ''.join(random.choice(chars) for _ in range(16))
        return f"flag{{{inner}}}".encode()
    elif method == 'flag_alnum32':
        chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'
        inner = ''.join(random.choice(chars) for _ in range(32))
        return f"flag{{{inner}}}".encode()
    elif method == 'donotctf_hex16':
        inner = ''.join(random.choice('0123456789abcdef') for _ in range(16))
        return f"donotctf{{{inner}}}".encode()
    elif method == 'donotctf_hex32':
        inner = ''.join(random.choice('0123456789abcdef') for _ in range(32))
        return f"donotctf{{{inner}}}".encode()
    elif method == 'donotctf_alnum16':
        chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'
        inner = ''.join(random.choice(chars) for _ in range(16))
        return f"donotctf{{{inner}}}".encode()
    elif method == 'donotctf_alnum32':
        chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'
        inner = ''.join(random.choice(chars) for _ in range(32))
        return f"donotctf{{{inner}}}".encode()
    elif method == 'random_string64':
        return ''.join(chr(random.randint(32,126)) for _ in range(64)).encode()
    elif method == 'uuid4':
        return f"donotctf{{{uuid.UUID(int=random.getrandbits(128))}}}".encode()
    elif method == 'seed_decimal':
        return str(seed).encode()
    elif method == 'hex64':
        # Gera 64 caracteres hex aleatórios (sem prefixo)
        return ''.join(random.choice('0123456789abcdef') for _ in range(64)).encode()
    return None

def main():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((HOST, PORT))
    banner = recv_until(sock)
    sock.close()
    print("[+] Banner:\n", banner)
    target = extract_hash(banner)
    if not target: return
    print(f"[+] Hash alvo: {target[:32]}...")

    methods = [
        'random_int', 'random_bytes',
        'getrandbits_little', 'getrandbits_big',
        'sha512_seed', 'sha512_seed_hex',
        'seed_decimal', 'seed_hex', 'seed_bytes_little', 'seed_bytes_big',
        'flag_hex16', 'flag_hex32', 'flag_alnum16', 'flag_alnum32',
        'donotctf_hex16', 'donotctf_hex32', 'donotctf_alnum16', 'donotctf_alnum32',
        'random_string64', 'uuid4', 'hex64'
    ]
    now = int(time.time())
    seeds = set()
    for t in range(now - WINDOW, now + WINDOW + 1):
        seeds.add(t)                     # inteiro
        seeds.add(t / 1.0)               # float (equivalente)
        seeds.add(t * 1000)              # milissegundos
        # pequenas variações (microssegundos)
        for frac in (0.1, 0.01, 0.001, 0.0001):
            seeds.add(t + frac)
            seeds.add(t - frac)

    total = len(seeds) * len(methods)
    print(f"[+] Testando {len(seeds)} sementes × {len(methods)} métodos = {total} combinações")

    count = 0
    for method in methods:
        print(f"[+] Método: {method}")
        for seed in seeds:
            count += 1
            if count % 10000 == 0:
                print(f"  X:   {count}/{total}")
            data = generate_flag(seed, method)
            if data is None: continue
            if isinstance(data, str): data = data.encode()
            h = hashlib.sha512(data).hexdigest()
            if h == target:
                print(f"\n✅ FLAG ENCONTRADA!")
                print(f"Semente: {seed}  |  Método: {method}")
                try:
                    print("Flag:", data.decode('utf-8'))
                except:
                    print("Flag (hex):", data.hex())
                return

    print("[!] Nada encontrado. Aumente WINDOW para 86400*7 (1 semana) e tente novamente.")
    print("    Ou verifique se o servidor usa uma semente fixa (ex.: tempo de criação).")

if __name__ == "__main__":
    main()