from pwn import remote

HOST = "98.94.69.132"
PORT = 32440

io = remote(HOST, PORT)

# banner inicial
print(io.recvuntil(b"Digite").decode(errors="ignore"))

# entradas escolhidas
inputs = [
    "a",
    "a",
    "aa",
    "aaa",
    "abc",
    "123",
    "",
]

for t in inputs:
    print(f"\n[+] Enviando: {repr(t)}")
    payload = t.encode() if isinstance(t, str) else t
    io.sendline(payload)

    # captura bytes/resposta sem depender do marcador "Digite"
    resposta = b""
    try:
        resposta = io.recv(timeout=2)
        # tenta pegar mais imediato se existir
        if resposta:
            try:
                resposta += io.recv(timeout=0.5)
            except Exception:
                pass
    except Exception:
        resposta = b""

    if not resposta:
        try:
            resposta = io.recvline(timeout=2)
        except Exception:
            resposta = b""

    print(resposta.decode(errors="ignore").strip())

# encerra
try:
    io.sendline(b"quit")
except Exception:
    pass

io.close()

