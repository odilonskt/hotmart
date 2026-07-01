import socket, time, random, re

HOST = '98.94.69.132'
PORT = 32440
TEXT = 'A' * 64
SEED = 1782916867  # a que você descobriu

def recv_until(sock, timeout=2.0):
    sock.settimeout(timeout)
    data = b''
    while True:
        try:
            chunk = sock.recv(4096)
            if not chunk: break
            data += chunk
            if b':' in data or b'>' in data:
                break
        except socket.timeout: break
    return data.decode(errors='ignore')

def send_command(sock, cmd):
    sock.send((cmd + '\n').encode())
    time.sleep(0.3)
    return recv_until(sock)

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect((HOST, PORT))
banner = recv_until(sock)
print("[+] Banner:")
print(banner)

# Envia 'A'*64
resp = send_command(sock, TEXT)
print("[+] Resposta do servidor:")
print(resp)

# Extrai o cifrado
match = re.search(r'[0-9a-f]{128,}', resp)
if match:
    cipher_hex = match.group(0)
    cipher = bytes.fromhex(cipher_hex)
    # Gera a chave com a semente conhecida
    random.seed(SEED)
    key = bytes([random.randint(0,255) for _ in range(64)])
    plain = bytes([cipher[i] ^ key[i] for i in range(64)])
    print("[+] Texto decifrado:", plain.decode(errors='ignore'))

    # Se o texto decifrado for uma pergunta, responda
    # Exemplo: se plain for "Qual é o resultado? 42", envie "42"
    # Aqui você precisa analisar o que veio. Por enquanto, envia de volta o plain
    # Mas cuidado: se plain for 'A'*64, isso não vai adiantar.
    # Tente enviar "flag" ou "response"
    final = send_command(sock, plain.decode(errors='ignore'))
    print("[+] Resposta final do servidor:")
    print(final)
else:
    print("[!] Cifrado não encontrado")
sock.close()