import socket
import time
import random
import hashlib
import re

HOST = '98.94.69.132'
PORT = 32440
WINDOW = 600  # segundos; aumente se necessário

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

def generate_key(seed, method='random_int'):
    if method == 'random_int':
        random.seed(seed)
        return bytes([random.randint(0, 255) for _ in range(64)])
    elif method == 'random_bytes':
        random.seed(seed)
        return random.randbytes(64)
    elif method == 'sha512_seed':
        return hashlib.sha512(str(seed).encode()).digest()[:64]
    elif method == 'sha512_full':
        return hashlib.sha512(str(seed).encode()).digest()
    else:
        return None

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

    # Testar vários métodos e sementes
    methods = ['random_int', 'random_bytes', 'sha512_seed', 'sha512_full']
    now = int(time.time())
    seeds = set()
    for t in range(now - WINDOW, now + WINDOW + 1):
        seeds.add(t)                # inteiro
        seeds.add(t / 1.0)          # float
        seeds.add(t * 1000)         # milissegundos
        # pequenas variações
        for frac in [0.1, 0.01, 0.001, 0.0001]:
            seeds.add(t + frac)
            seeds.add(t - frac)

    print(f"[+] Testando {len(seeds)} sementes em {len(methods)} métodos...")

    for method in methods:
        print(f"[+] Método: {method}")
        for seed in seeds:
            key = generate_key(seed, method)
            if key is None:
                continue
            h = hashlib.sha512(key).hexdigest()
            if h == target_hash:
                print(f"\n[+] FLAG ENCONTRADA!")
                print(f"Semente: {seed} (método {method})")
                print("Flag (hex):", key.hex())
                try:
                    print("Flag (ASCII):", key.decode('utf-8'))
                except:
                    pass
                return

    print("[!] Nenhuma combinação encontrada. Aumente WINDOW ou tente outros métodos.")
    print("    Considere que a semente pode ser um timestamp de quando o servidor foi iniciado, não agora.")

if __name__ == "__main__":
    main()