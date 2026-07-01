import random
import hashlib
import re

seed = 1782916867
# Cole aqui o hash que você obteve em uma das execuções (ex.: o de 4288fc11...)
target = "99ba5ec7c0f50ec1edd70c0b2a71a19363d3fd73ed6b8acc77a768136463bd7629ca008a7a6fa70894603371eecad37d13ae4b694d175b97aa6d6546bb4563887a5bb20035c6"

def test(desc, data):
    if isinstance(data, str):
        data = data.encode()
    h = hashlib.sha512(data).hexdigest()
    if h == target:
        print(f"✅ FLAG: {desc}")
        print(data.decode())
        return True
    return False

# 1. Formato Donotecho{...} com caracteres especiais
charset = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_@!'
for length in [16, 20, 24, 32]:
    random.seed(seed)
    inner = ''.join(random.choice(charset) for _ in range(length))
    if test(f"Donotecho{{{length}}}", f"Donotecho{{{inner}}}"):
        exit()

# 2. Formato donotctf{...} (caso seja minúsculo)
charset2 = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_@!'
for length in [16, 20, 24, 32]:
    random.seed(seed)
    inner = ''.join(random.choice(charset2) for _ in range(length))
    if test(f"donotctf{{{length}}}", f"donotctf{{{inner}}}"):
        exit()

# 3. Apenas hex (sem prefixo) – 64 caracteres
random.seed(seed)
hex_str = ''.join(random.choice('0123456789abcdef') for _ in range(64))
test("hex64", hex_str)

# 4. Flag com prefixo "flag{...}"
random.seed(seed)
flag_hex = f"flag{{{''.join(random.choice('0123456789abcdef') for _ in range(16))}}}"
test("flag_hex16", flag_hex)

print("Nenhum formato bateu com a semente atual.")