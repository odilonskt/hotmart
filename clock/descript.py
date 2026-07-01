import random
import hashlib
import base64
import uuid

seed = 1782916867
target = "901d9306eb9673e95f9382cc168581ce00e7d7917cadbf0f30306a94c099c21d9229671d0626113e2ee51092a8b2ae9d5707822e0583025ac7811767caef21f0d059513f7626"

def test(desc, data):
    if isinstance(data, str):
        data = data.encode()
    h = hashlib.sha512(data).hexdigest()
    if h == target:
        print(f"✅ FLAG: {desc}")
        print(data.decode() if isinstance(data, bytes) and all(32 <= c < 127 for c in data) else data.hex())
        return True
    return False

# 1. random.getrandbits(512) em little e big (já feito, mas repetimos)
random.seed(seed)
test("getrandbits(512) little", random.getrandbits(512).to_bytes(64, 'little'))
random.seed(seed)
test("getrandbits(512) big", random.getrandbits(512).to_bytes(64, 'big'))

# 2. SHA-512 da semente em várias representações
test("sha512(str(seed))", hashlib.sha512(str(seed).encode()).digest())
test("sha512(bytes(seed))", hashlib.sha512(seed.to_bytes(8, 'little')).digest())
test("sha512(hex(seed))", hashlib.sha512(hex(seed).encode()).digest())

# 3. String aleatória com 64 caracteres imprimíveis (já feito)
random.seed(seed)
chars = ''.join(chr(random.randint(32,126)) for _ in range(64))
test("random string 64 ASCII", chars)

# 4. donotctf{...} com inner de tamanhos e charsets variados
for inner_len in [8, 12, 16, 20, 32]:
    for charset in ['0123456789abcdef', 'abcdefghijklmnopqrstuvwxyz', 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789']:
        random.seed(seed)
        inner = ''.join(random.choice(charset) for _ in range(inner_len))
        flag = f"donotctf{{{inner}}}"
        test(f"donotctf{{{inner_len},{charset[:4]}}}", flag)

# 5. Flag com SHA-512 da semente em hex (128 caracteres) truncada em diferentes tamanhos
h = hashlib.sha512(str(seed).encode()).hexdigest()
for size in [32, 64, 128]:
    test(f"flag=donotctf{{{h[:size]}}}", f"donotctf{{{h[:size]}}}")

# 6. Base64 do SHA-512 da semente
b64 = base64.b64encode(hashlib.sha512(str(seed).encode()).digest()).decode()
test("flag=donotctf{base64(sha512)}", f"donotctf{{{b64[:32]}}}")

# 7. UUID v4 gerado com random
random.seed(seed)
u = str(uuid.UUID(int=random.getrandbits(128)))
test("flag=donotctf{uuid4}", f"donotctf{{{u}}}")

# 8. SHA-512 da semente como bytes -> hex (já feito, mas com tamanho fixo)
h_full = hashlib.sha512(str(seed).encode()).hexdigest()
test("sha512(seed) hex full", h_full.encode())

print("Nenhuma variação bateu. A semente para a flag é outra, ou a flag é obtida interativamente.")