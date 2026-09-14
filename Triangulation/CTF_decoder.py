import re
import binascii
from datetime import datetime

print("="*60)
print(" HIPÓTESE A: TAMANHOS DE RESPOSTA 200 (NGINX)")
print("="*60)

# Mapeia TODO tamanho entre 32 e 126 como caractere ASCII
scanner_agents = ['dirbuster', 'Nikto', 'sqlmap', 'sqlmap/1.7.2#stable', 'PostmanRuntime']
entries = []

with open('nginx.log', 'r', encoding='utf-8', errors='ignore') as f:
    for line in f:
        # Pula scanners conhecidos
        if any(agent in line for agent in scanner_agents):
            continue
        
        match = re.search(r'\[(.*?)\] ".*?" 200 (\d+) ', line)
        if match:
            ts_str = match.group(1)
            size = int(match.group(2))
            if 32 <= size <= 126:
                try:
                    ts = datetime.strptime(ts_str, '%d/%b/%Y:%H:%M:%S %z')
                    entries.append((ts, chr(size)))
                except:
                    pass

entries.sort(key=lambda x: x[0])
flag_a = ''.join(ch for _, ch in entries)
print(f"Flag A (Tamanhos < 127 filtrados e ordenados): {flag_a}")


print("\n" + "="*60)
print(" HIPÓTESE B: USUÁRIOS SUSPEITOS E SESSION_CTX")
print("="*60)
users = ['guest_sync', 'db_maintainer', 'backup_runner', 'root_internal']
# Os 4 session_ctx correspondentes encontrados no app.log
ctxs = [
    "656f707379686b7170217079",
    "6d74336378773c7034646f34",
    "685f653477753b75357934",
    "346f5f3377646b3c7b6523"
]

for i, u in enumerate(users):
    dec = binascii.unhexlify(ctxs[i]).decode('ascii')
    print(f"User: {u:<15} | Hex: {ctxs[i]} | ASCII: {dec}")

print("\nTentativa de XOR com os usernames (se o tamanho permitir):")
for i, u in enumerate(users):
    dec_bytes = binascii.unhexlify(ctxs[i])
    u_bytes = u.encode('ascii')
    # XOR até onde der
    xor_res = ''.join(chr(b ^ u_bytes[j % len(u_bytes)]) for j, b in enumerate(dec_bytes))
    print(f"{u:<15} XOR session_ctx -> {xor_res}")


print("\n" + "="*60)
print(" HIPÓTESE C: QUERIES DO NIKTO")
print("="*60)
queries = []
with open('nginx.log', 'r', encoding='utf-8', errors='ignore') as f:
    for line in f:
        m = re.search(r'query=(\d+)', line)
        if m:
            queries.append(int(m.group(1)))

chars = [chr(q) if 32 <= q <= 126 else '?' for q in queries]
print("Query chars do Nikto:", ''.join(chars).replace('?', ''))

print("\n" + "="*60)
print(" HIPÓTESE D: REQ_REFS DO APP.LOG (Valores Inteiros)")
print("="*60)
# A hipótese de extrair ASCII puro dos req_refs no momento do ataque
with open('app.log', 'r', encoding='utf-8', errors='ignore') as f:
    content = f.read()

refs = re.findall(r'req_ref: (0x[0-9a-fA-F]+)', content)
vals = [int(r, 16) for r in refs]

# Pega o último byte (LSB) de todos
lsb_chars = "".join(chr(v & 0xFF) for v in vals if 32 <= (v & 0xFF) <= 126)
print("LSB ASCII (req_refs totais):", lsb_chars[:100], "...")

print("\nConcluído. Analise os resultados acima para encontrar a flag!")
