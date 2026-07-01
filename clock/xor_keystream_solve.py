from pwn import remote
import re

HOST = "98.94.69.132"
PORT = 32440


def recv_until(io, marker=b"Digite", timeout=5):
    return io.recvuntil(marker, timeout=timeout)


def extract_hex_from_line(s: bytes):
    # captura 2 ou mais bytes em hex (ex: 94 0d ... removendo espaços se existirem)
    m = re.search(rb"Encrypted:\s*([0-9a-fA-F\s]+)", s)
    if not m:
        # fallback: qualquer sequência hex grande
        m2 = re.search(rb"([0-9a-fA-F]{2,})", s)
        if not m2:
            return None
        return m2.group(1).replace(b" ", b"")

    return m.group(1).replace(b" ", b"")


def main():
    io = remote(HOST, PORT)

    # banner inicial (contém a flag cifrada)
    banner = io.recvuntil(b"Digite", timeout=10)
    # tenta achar "A Flag:" (hex)
    flag_hex = None
    m = re.search(rb"A\s*Flag\s*:\s*([0-9a-fA-F\s]+)", banner)
    if m:
        flag_hex = m.group(1).replace(b" ", b"")

    if not flag_hex:
        # fallback: procura qualquer hex grande no banner (apenas [0-9a-f] e ignora lixo)
        m2 = re.search(rb"([0-9a-fA-F]{10,})", banner)
        if m2:
            flag_hex = m2.group(1).replace(b" ", b"")

    if not flag_hex:
        raise RuntimeError("Nao consegui extrair a flag cifrada do banner")

    # limpa tudo que nao for hex
    flag_hex = re.sub(rb"[^0-9a-fA-F]", b"", flag_hex)

    if len(flag_hex) % 2 != 0:
        # fromhex exige tamanho par
        flag_hex = flag_hex[:-1]


    # Envia 70 vezes 'A' para recuperar keystream por posição
    payload = b"A" * 70
    io.sendline(payload)

    # captura a linha com Encrypted
    out = io.recvline(timeout=10)
    # às vezes vem em múltiplas linhas
    if b"Encrypted" not in out:
        try:
            out += io.recvuntil(b"\n", timeout=2)
        except Exception:
            pass

    cipher_hex_bytes = extract_hex_from_line(out)
    if not cipher_hex_bytes:
        raise RuntimeError("Nao consegui extrair ciphertext do response")

    ciphertext = bytes.fromhex(cipher_hex_bytes.decode())

    if len(ciphertext) < 70:
        # alguns servidores podem limitar o output; ainda assim dá pra continuar
        keystream_len = len(ciphertext)
    else:
        keystream_len = 70

    keystream = bytes([ciphertext[i] ^ ord('A') for i in range(keystream_len)])

    flag_cipher = bytes.fromhex(flag_hex.decode())
    flag_plain = bytes([flag_cipher[i] ^ keystream[i] for i in range(min(len(flag_cipher), len(keystream)))])

    print("[+] Cipher flag hex:", flag_hex.decode())
    print("[+] Keystream (hex):", keystream.hex())
    print("[+] Flag plain (parcial se keystream curta):")
    print(flag_plain)
    try:
        print(flag_plain.decode('utf-8'))
    except Exception:
        pass

    io.close()


if __name__ == "__main__":
    main()

