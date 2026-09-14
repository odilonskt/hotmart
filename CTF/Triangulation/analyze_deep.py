#!/usr/bin/env python3
"""
Análise aprofundada focada nos vetores suspeitos
"""
import re
from urllib.parse import unquote
from collections import defaultdict, Counter

SUSPICIOUS_IPS = {'198.51.100.10', '198.51.100.20', '198.51.100.30'}
RECON_ENDPOINTS = ['/.git/config', '/config.json', '/wp-admin', '/administrator',
                   '/.env', '/backup', '/phpmyadmin', '/shell']

# ─── NGINX: Análise dos IPs suspeitos ────────────────────────────────────────
print("=" * 80)
print("ANÁLISE FOCADA: IPs 198.51.100.x (TEST-NET — NUNCA em tráfego real)")
print("=" * 80)

nginx_pattern = re.compile(
    r'^(\S+) - - \[([^\]]+)\] "(\S+) (\S+) HTTP/[^"]+" (\d{3}) (\d+) "[^"]*" "([^"]*)"'
)

suspicious_activity = defaultdict(list)
all_entries = []
recon_hits = []
product_ids = set()

with open('nginx.log', 'r', encoding='utf-8', errors='ignore') as f:
    for line in f:
        m = nginx_pattern.match(line.strip())
        if not m:
            continue
        ip, ts, method, url, status, size, ua = m.groups()
        status = int(status)
        size = int(size)
        decoded_url = unquote(url)
        endpoint = decoded_url.split('?')[0]
        
        entry = {'ip': ip, 'ts': ts, 'method': method, 'url': decoded_url,
                 'endpoint': endpoint, 'status': status, 'size': size, 'ua': ua}
        all_entries.append(entry)
        
        if ip in SUSPICIOUS_IPS:
            suspicious_activity[ip].append(entry)
        
        # Recon endpoints
        if any(r in decoded_url for r in RECON_ENDPOINTS):
            recon_hits.append(entry)
        
        # Product IDs
        m2 = re.search(r'/products/view\?id=(\d+)', decoded_url)
        if m2:
            product_ids.add(m2.group(1))

# Relatório por IP suspeito
for ip in sorted(SUSPICIOUS_IPS):
    entries = suspicious_activity[ip]
    if not entries:
        print(f"\n[{ip}] Não encontrado")
        continue
    
    print(f"\n{'─'*60}")
    print(f"[{ip}] — {len(entries)} requests")
    
    # Status codes
    sc = Counter(e['status'] for e in entries)
    print(f"  Status: {dict(sc)}")
    
    # Endpoints
    ep_counter = Counter(e['endpoint'] for e in entries)
    print(f"  Endpoints únicos: {len(ep_counter)}")
    print(f"  Top endpoints:")
    for ep, cnt in ep_counter.most_common(15):
        print(f"    ({cnt:3d}x) {ep}")
    
    # User agents
    ua_counter = Counter(e['ua'] for e in entries)
    print(f"  User-agents:")
    for ua, cnt in ua_counter.most_common(5):
        print(f"    ({cnt}x) {ua[:80]}")
    
    # Requisições 403/404
    errors = [e for e in entries if e['status'] in (403, 404)]
    print(f"\n  === 403/404 (possível exfil/recon) — {len(errors)} hits ===")
    for e in errors[:20]:
        print(f"    [{e['status']}] {e['ts']} | {e['method']} {e['url']}")
    
    # Primeiro e último request
    print(f"\n  Primeiro: {entries[0]['ts']} | {entries[0]['method']} {entries[0]['url']}")
    print(f"  Último:   {entries[-1]['ts']} | {entries[-1]['method']} {entries[-1]['url']}")

# ─── RECON ENDPOINTS ────────────────────────────────────────────────────────
print(f"\n{'='*80}")
print(f"ENDPOINTS DE RECONHECIMENTO — {len(recon_hits)} hits")
print(f"{'='*80}")
ip_recon = Counter(e['ip'] for e in recon_hits)
print("\nIPs que fizeram recon:")
for ip, cnt in ip_recon.most_common():
    print(f"  {ip}: {cnt}x")

# Quais endpoints foram atingidos por 198.51.100.x
print("\nRecon feito pelos IPs suspeitos:")
for e in recon_hits:
    if e['ip'] in SUSPICIOUS_IPS:
        print(f"  [{e['status']}] {e['ip']} | {e['url']}")

# ─── PRODUCT IDs ────────────────────────────────────────────────────────────
print(f"\n{'='*80}")
print(f"PRODUCT IDs encontrados no nginx: {sorted(product_ids)}")
print(f"{'='*80}")

# Algum produto específico acessado só pelos 198.51.100.x?
prod_by_suspicious = defaultdict(set)
for e in all_entries:
    if e['ip'] in SUSPICIOUS_IPS:
        m2 = re.search(r'/products/view\?id=(\d+)', e['url'])
        if m2:
            prod_by_suspicious[e['ip']].add(m2.group(1))
print("Produtos acessados pelos IPs suspeitos:")
for ip, ids in prod_by_suspicious.items():
    print(f"  {ip}: {sorted(ids)}")

# ─── SEQUÊNCIA TEMPORAL dos 198.51.100.x ─────────────────────────────────
print(f"\n{'='*80}")
print("SEQUÊNCIA TEMPORAL dos IPs suspeitos (primeiras 20 requisições de cada)")
print(f"{'='*80}")
for ip in sorted(SUSPICIOUS_IPS):
    entries = suspicious_activity[ip]
    print(f"\n[{ip}]")
    for e in entries[:20]:
        print(f"  {e['ts']} [{e['status']}] {e['method']} {e['url'][:100]}")

# ─── REQ_REFS: decodificação avançada ──────────────────────────────────────
print(f"\n{'='*80}")
print("REQ_REFS: Decodificação Avançada (426 valores)")
print(f"{'='*80}")

with open('app.log', 'r', encoding='utf-8', errors='ignore') as f:
    content = f.read()

refs = re.findall(r'req_ref: (0x[0-9a-fA-F]+)', content)
vals = [int(r, 16) for r in refs]

# Estatísticas
print(f"Total: {len(vals)}")
print(f"Min: {min(vals):,} (0x{min(vals):x})")
print(f"Max: {max(vals):,} (0x{max(vals):x})")
print(f"Valores únicos: {len(set(vals))}")

# Byte mais baixo (ASCII)
lsb = [v & 0xFF for v in vals]
lsb_printable = ''.join(chr(b) if 32 <= b <= 126 else f'[{b:02x}]' for b in lsb)
print(f"\nByte LSB de cada ref (os primeiros 50):")
print(f"  {''.join(chr(b) if 32 <= b <= 126 else '.' for b in lsb[:50])}")
print(f"\nByte LSB completo:")
print('  ' + ''.join(chr(b) if 32 <= b <= 126 else '.' for b in lsb))

# Tentar nibbles do meio
nibbles_mid = [(v >> 8) & 0xFF for v in vals]
print(f"\nByte do meio (v>>8 & 0xFF):")
print('  ' + ''.join(chr(b) if 32 <= b <= 126 else '.' for b in nibbles_mid))

# Tentar byte alto  
high = [(v >> 16) & 0xFF for v in vals]
print(f"\nByte alto (v>>16 & 0xFF):")
print('  ' + ''.join(chr(b) if 32 <= b <= 126 else '.' for b in high))

# Tentar XOR com 0x42 no LSB
xor42 = [(v & 0xFF) ^ 0x42 for v in vals]
print(f"\nLSB XOR 0x42:")
print('  ' + ''.join(chr(b) if 32 <= b <= 126 else '.' for b in xor42))

# Tentar dividir por algum valor e pegar parte inteira como ASCII
# Cada valor como 3 bytes (ignorar byte mais alto)
print(f"\nCada ref como 3 bytes (ignorar byte mais alto):")
three_byte_str = ''
for v in vals[:50]:
    b1 = (v >> 16) & 0xFF
    b2 = (v >> 8) & 0xFF
    b3 = v & 0xFF
    for b in [b1, b2, b3]:
        three_byte_str += chr(b) if 32 <= b <= 126 else '.'
print('  ' + three_byte_str)

# Pares de refs como lat/lon (hipótese Triangulation)
print(f"\nHipótese: pares de refs como coordenadas GPS (/ 1e6)")
for i in range(0, min(len(vals)-1, 10), 2):
    lat = vals[i] / 1e6
    lon = vals[i+1] / 1e6
    print(f"  ({lat:.4f}, {lon:.4f})")

# Hipótese: cada ref é um número de 7 dígitos dividido de forma diferente
# Vamos ver se algum sub-conjunto dos bytes forma algo legível
print(f"\nPrimeiros 30 refs (hex, decimal, bytes):")
for i, (r, v) in enumerate(zip(refs[:30], vals[:30])):
    b = v.to_bytes(4, 'big')
    ascii_try = ''.join(chr(x) if 32 <= x <= 126 else '.' for x in b)
    print(f"  [{i:2d}] {r:12s} = {v:10d} -> {b.hex()} -> '{ascii_try}'")

# ─── SYSLOG: IP 10.0.0.42 com users únicos ───────────────────────────────
print(f"\n{'='*80}")
print("SYSLOG: Atividade do IP 10.0.0.42 (users únicos)")
print(f"{'='*80}")

ip42_entries = []
with open('syslog(1).log', 'r', encoding='utf-8', errors='ignore') as f:
    for line in f:
        if '10.0.0.42' in line:
            ip42_entries.append(line.strip())
            print(f"  {line.strip()}")

# Extrair usernames
unique_users_42 = re.findall(r'invalid user (\S+) from 10\.0\.0\.42', '\n'.join(ip42_entries))
print(f"\nUsernames únicos de 10.0.0.42: {unique_users_42}")

# Possível encoding nos usernames?
print(f"\nConcatenação dos usernames: {'_'.join(unique_users_42)}")
print(f"Primeiras letras: {''.join(u[0] for u in unique_users_42)}")
print(f"Iniciais: {' '.join(u[:3] for u in unique_users_42)}")
