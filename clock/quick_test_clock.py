from pwn import remote

HOST = "98.94.69.132"
PORT = 32440

io = remote(HOST, PORT)

# tenta capturar banner/prompt inicial
try:
    data0 = io.recv(timeout=2)
    if data0:
        print("[banner/initial]", data0.decode(errors="ignore"))
except Exception:
    pass

tests = ["a", "a", "aa", "abc", "123"]
for s in tests:
    io.sendline(s.encode())
    # tenta ler resposta
    r = b""
    try:
        r = io.recvline(timeout=2)
    except Exception:
        pass
    if not r:
        try:
            r = io.recv(timeout=2)
        except Exception:
            pass
    print(f"{s!r} -> {r.decode(errors='ignore').strip()}")

io.close()

