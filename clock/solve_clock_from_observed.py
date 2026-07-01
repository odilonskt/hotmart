import re
import socket
import time
import hashlib

HOST = "98.94.69.132"
PORT = 32440

# Observado no teste manual:
#  a  -> Encrypted: aa
#  a  -> Encrypted: aa
#  aa -> Encrypted: aa18
#  abc -> Encrypted: aa1bb9
# 123 -> Encrypted: fa4be9
# Isso sugere que o servidor calcula algo determinístico e que o texto altera
# principalmente o prefixo/sufixo do hexdigest, e que existe um sufixo baseado em timestamp.
# Vamos identificar a construção: procura SHA-512 hex (128 chars) ou outro hash.

# Estratégia: explorar se o output é concatenação de:
#   hash(texto).hexdigest()[:?] + timestamp_hex[:?]
# e se o timestamp tem tamanho fixo (no output final)

def recv_until(sock, markers=(b"Digite", b"quit", b"A Flag:") , timeout=2.0):
    sock.settimeout(timeout)
    data = b""
    while True:
        try:
            chunk = sock.recv(4096)
            if not chunk:
                break
            data += chunk
            if any(m in data for m in markers):
                break
        except Exception:
            break
    return data


def parse_encrypted_line(s: str):
    # Ex: "Encrypted: aa1bb9"
    m = re.search(r"Encrypted:\s*([0-9a-fA-F]+)", s)
    return m.group(1).lower() if m else None


def query(io, text: str):
    io.sendline(text.encode())


def main():
    # Usamos sockets simples para evitar dependência de pwntools.
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((HOST, PORT))
    banner = recv_until(s, timeout=2.0)
    banner_text = banner.decode(errors="ignore")
    print(banner_text)

    # extrai a Flag se o servidor imprime
    mflag = re.search(r"A Flag:\s*([0-9a-fA-F]+)", banner_text)
    if mflag:
        print("[+] Flag (já fornecida no banner):", mflag.group(1))

    # Agora captura 1 rodada com entradas conhecidas para inferir fórmula.
    # (o desafio pode encerrar depois de 'quit')
    tests = ["a", "a", "aa", "abc", "123"]
    outputs = []
    for t in tests:
        _ = recv_until(s, markers=(b"Digite"), timeout=2.5)
        s.sendall((t + "\n").encode())
        resp = recv_until(s, timeout=2.5)
        out = resp.decode(errors="ignore")
        enc = parse_encrypted_line(out)
        outputs.append((t, enc, out.strip()))
        print(t, "->", enc)

    s.close()

    print("\n[+] Outputs:")
    for t, enc, _raw in outputs:
        print(f"    {t!r}: {enc}")

    # Observação do teste anterior:
    # 'a' -> aa (2 hex)
    # Isso é incompatível com SHA-512 completo (128 hex). Logo não é diretamente sha512(texto).hexdigest().
    # Com base no valor recebido no seu post (140 hex chars), a função do desafio pode ser:
    #   SHA512(texto + timestamp).hexdigest() + timestamp_hex(12 chars)
    # porém o output atual (Encrypted: aa...) parece truncado.
    # Sem reexecutar com captura do timestamp exato (ou sem ver o código do servidor),
    # a forma determinística exata não dá pra deduzir 100% só com 5 exemplos.
    print("\n[!] Com os 5 exemplos observados, não é possível inferir unicamente a construção criptográfica.")
    print("    Porém, o servidor já imprime 'A Flag' no banner. Esse valor é a resposta final.")


if __name__ == "__main__":
    main()

