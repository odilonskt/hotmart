import re, json, base64, binascii
from collections import Counter, defaultdict

print('='*70)
print('ANALISE DO APP.LOG - Procurando padroes de criptografia')
print('='*70)

# Extrair req_ref hex values do app.log
with open('app.log', 'r', encoding='utf-8') as f:
    content = f.read()

hex_refs = re.findall(r'req_ref: (0x[0-9a-fA-F]+)', content)
print(f'Total req_ref encontrados: {len(hex_refs)}')

# Converter hex para chars
print('\nHex -> Decimal -> ASCII:')
chars = []
for h in hex_refs:
    val = int(h, 16)
    try:
        b = val.to_bytes((val.bit_length() + 7) // 8, 'big')
        decoded = b.decode('ascii', errors='replace')
        chars.append(decoded)
    except Exception as e:
        chars.append('?')
        decoded = '?'

# Tentar concatenar
print('\nTentando concatenar todos os chars:')
all_concat = ''.join(chars)
print(f'Resultado: {all_concat}')

# Apenas os primeiros bytes de cada hex
print('\nApenas primeiro byte de cada:')
first_bytes = []
for h in hex_refs:
    val = int(h, 16)
    first_byte = val & 0xFF
    try:
        c = chr(first_byte)
        first_bytes.append(c)
    except:
        first_bytes.append('?')
print(''.join(first_bytes))

# Apenas ultimo byte
print('\nApenas ultimo byte de cada:')
last_bytes = []
for h in hex_refs:
    val = int(h, 16)
    last_byte = val & 0xFF
    last_bytes.append(chr(last_byte) if 32 <= last_byte < 127 else f'[{last_byte}]')
print(''.join(last_bytes[:100]))

# Tentar como sequencia de bytes
print('\n\nComo sequencia de bytes (todos os hex concatenados):')
all_bytes = b''
for h in hex_refs:
    val = int(h, 16)
    try:
        b = val.to_bytes((val.bit_length() + 7) // 8, 'big')
        all_bytes += b
    except:
        pass

# Tentar decodificar como ASCII
try:
    print('Como ASCII:', all_bytes[:200].decode('ascii', errors='replace'))
except:
    pass

# Tentar base64
try:
    b64_decoded = base64.b64decode(all_bytes)
    print('Como base64:', b64_decoded[:200])
except:
    pass

print('\n' + '='*70)
print('ANALISE DO NGINX.LOG - Procurando padroes anomalos')
print('='*70)

with open('nginx.log', 'r', encoding='utf-8') as f:
    nginx_lines = f.readlines()

print(f'Total de linhas: {len(nginx_lines)}')

# Encontrar requests suspeitos
suspicious = []
for i, line in enumerate(nginx_lines):
    # 401 responses - login failures
    if ' 401 ' in line:
        suspicious.append(('401', i+1, line.strip()[:120]))
    # Requests anomalos (tamanho pequeno ou grande)
    # Endpoints incomuns
    if '/admin' in line or '/secret' in line or '/flag' in line or '/ctf' in line:
        suspicious.append(('ENDPOINT', i+1, line.strip()[:120]))

print(f'\nRequests suspeitos: {len(suspicious)}')
for typ, ln, l in suspicious[:30]:
    print(f'  [{typ}] L{ln}: {l}')

# Extrair user-agents unicos
agents = set()
for line in nginx_lines:
    m = re.search(r'"([^"]+)"$', line)
    if m:
        agents.add(m.group(1))
print(f'\nUser-agents unicos: {len(agents)}')
for a in sorted(agents)[:20]:
    print(f'  {a}')

# Analisar endpoints
endpoints = Counter()
for line in nginx_lines:
    m = re.search(r'"[A-Z]+ (/[^\s?"]*)', line)
    if m:
        endpoints[m.group(1)] += 1
print('\nEndpoints mais frequentes:')
for ep, cnt in endpoints.most_common(20):
    print(f'  {ep}: {cnt}')

# Procurar por tamanhos de resposta suspeitos
sizes = []
for line in nginx_lines:
    m = re.search(r'" \d{3} (\d+) ', line)
    if m:
        sizes.append(int(m.group(1)))

# Verificar se os tamanhos formam uma mensagem
print(f'\nTotal de respostas com tamanho: {len(sizes)}')
print(f'Tamanhos unicos: {sorted(set(sizes))[:50]}')

# Tamanhos como ASCII?
unique_sizes = sorted(set(sizes))
print('\nTamanhos convertidos para ASCII:')
for s in unique_sizes:
    if 32 <= s < 127:
        print(f'  {s} -> {chr(s)}')

print('\n' + '='*70)
print('ANALISE DO SYSLOG - Procurando padroes anomalos')
print('='*70)

with open('syslog(1).log', 'r', encoding='utf-8') as f:
    syslog_lines = f.readlines()

print(f'Total de linhas: {len(syslog_lines)}')

# IPs que fizeram login com sucesso
accepted_ips = []
for line in syslog_lines:
    if 'Accepted password' in line:
        m = re.search(r'Accepted password for (\S+) from (\S+)', line)
        if m:
            accepted_ips.append((m.group(1), m.group(2), line.strip()[:100]))

print(f'\nLogins aceitos: {len(accepted_ips)}')
for user, ip, l in accepted_ips[:30]:
    print(f'  {user} from {ip}')

# usuarios especiais/incomuns
failed_users = []
for line in syslog_lines:
    if 'Failed password for invalid user' in line:
        m = re.search(r'invalid user (\S+)', line)
        if m:
            user = m.group(1)
            if user not in ['test', 'admin', 'root', 'ubuntu', 'mysql', 'postgres', 'backup', 'ftpuser', 'user']:
                failed_users.append((user, line.strip()[:100]))

print(f'\nUsuarios invalidos INCOMUNS que tentaram login:')
for user, l in failed_users:
    print(f'  {user}: {l}')
